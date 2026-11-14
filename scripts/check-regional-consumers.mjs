import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const ownRoot=fileURLToPath(new URL('../',import.meta.url));
const root=process.argv.length===2?ownRoot:process.argv.length===4&&process.argv[2]==='--root'?resolve(process.argv[3]):null;
if(!root)throw Error('Usage: node scripts/check-regional-consumers.mjs [--root CHECKOUT]');
for(const path of ['src/services/arc/src/service.rs','src/services/lab/test/regional-arc-runtime.test.ts',
  'src/services/lab/src/client/regional.ts','src/services/gateway/test/holder-client-integration.test.mjs']){
  if(!existsSync(resolve(root,path)))throw Error('Regional consumer prerequisites are missing; this is not a passing integration check.');
}
function execute(command,args,{inherit=false,timeout=30000}={}){
  const result=spawnSync(command,args,{cwd:root,encoding:'utf8',shell:false,windowsHide:true,timeout,maxBuffer:4*1024*1024,
    stdio:inherit?'inherit':'pipe'});
  if(result.error||result.status!==0)throw Error('Regional consumer operation failed: '+command);
  return result.stdout?.trim()??'';
}
const git=(...args)=>execute('git',args);
const revision=git('log','-1','--format=%H','--','src/services/arc');
if(!/^[0-9a-f]{40}$/.test(revision)||git('status','--porcelain','--','src/services/arc'))throw Error('ARC source must be committed before integration validation.');
git('diff','--exit-code',revision,'--','src/services/arc');
const docker=(args,options)=>execute('docker',args,options);
const arc='tokenforge-arc:interop',consumer='tokenforge-regional:consumer-tests';
docker(['build','--build-arg',`TF_ARC_SOURCE_REVISION=${revision}`,'-f','src/services/arc/Dockerfile','-t',arc,'.'],{inherit:true,timeout:900000});
docker(['build','--build-arg',`ARC_IMAGE=${arc}`,'--build-arg',`TF_ARC_SOURCE_REVISION=${revision}`,
  '-f',resolve(ownRoot,'scripts/regional-consumer.Dockerfile'),'-t',consumer,'.'],{inherit:true,timeout:300000});
let redis='';
try{
  const redisId=docker(['run','-d','--rm','--network','none','--user','redis','--read-only','--tmpfs','/data:rw,noexec,nosuid,size=8m',
    '--add-host','protected-origin:127.0.0.1','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','384m',
    '--pids-limit','64','--log-driver','none','--label',`tokenforge.test=regional-consumers-${process.pid}`,
    'redis@sha256:efc27681bf81e6ed55cb581718b7818c6c04c39b1f9aa40854edd3ea2241b6ed',
    'redis-server','--bind','127.0.0.1','--save','','--appendonly','no','--maxmemory','268435456','--maxmemory-policy','noeviction',
    '--slowlog-log-slower-than','-1','--slowlog-max-len','0','--acllog-max-len','0']);
  if(!/^[0-9a-f]{64}$/.test(redisId))throw Error('Regional test container identity invalid');
  redis=redisId;
  let ready=false;
  for(let n=0;n<20;n++){
    try{ready=docker(['exec',redis,'redis-cli','PING'])==='PONG';}catch{/* bounded startup only */}
    if(ready)break;await delay(100);
  }
  if(!ready)throw Error('Regional test Redis startup failed');
  // Suppress assertion details: third-party failures must not print test proofs/credentials.
  const output=docker(['run','--rm','--network',`container:${redis}`,'--user','node','--read-only','--cap-drop','ALL',
    '--security-opt','no-new-privileges','--memory','384m','--pids-limit','64','--log-driver','none',consumer],{timeout:120000});
  const tests=Number(/\btests (\d+)\b/.exec(output)?.[1]),passed=Number(/\bpass (\d+)\b/.exec(output)?.[1]);
  if(!Number.isSafeInteger(tests)||tests<2||passed!==tests||!/\bfail 0\b/.test(output)||!/\bcancelled 0\b/.test(output)
    ||!/\bskip(?:ped)? 0\b/.test(output))throw Error('All native consumer tests must execute without skips.');
  console.log(`PASS: actual Rust ARC/admission/helper and actual holder client/gateway/Redis consumer tests; ${passed} passed, 0 skipped.`);
}finally{if(redis)docker(['rm','-f',redis]);}
