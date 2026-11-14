import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { createTestTls } from './create-test-tls.ts';
const root=fileURLToPath(new URL('../../../../',import.meta.url));
const image='tokenforge-gateway:regional-tests';
const redis='redis@sha256:efc27681bf81e6ed55cb581718b7818c6c04c39b1f9aa40854edd3ea2241b6ed';
function docker(args,inherit=false,input){
  const r=spawnSync('docker',args,{cwd:root,encoding:'utf8',shell:false,input,timeout:180000,maxBuffer:1024*1024,
    stdio:inherit?[input===undefined?'inherit':'pipe','inherit','inherit']:'pipe'});
  if(r.error||r.status!==0)throw Error('Regional integration Docker operation failed');return r.stdout?.trim()??'';
}
const tls=await createTestTls();
docker(['build','--target','regional-tests','-f','src/services/gateway/Dockerfile','-t',image,'.'],true);
let id='';
try{
  id=docker(['run','-d','--rm','--network','none','--user','redis','--read-only','--tmpfs','/data:rw,noexec,nosuid,size=8m',
    '--add-host','redis:127.0.0.1','--add-host','protected-origin:127.0.0.1','--cap-drop','ALL','--security-opt','no-new-privileges',
    '--memory','384m','--pids-limit','64','--log-driver','none','--label',`tokenforge.test=holder-integration-${process.pid}`,
    redis,'redis-server','--bind','127.0.0.1','--save','','--appendonly','no','--maxmemory','268435456',
    '--maxmemory-policy','noeviction','--slowlog-log-slower-than','-1','--slowlog-max-len','0','--acllog-max-len','0']);
  let ready=false;
  for(let n=0;n<20;n++){try{ready=docker(['exec',id,'redis-cli','PING'])==='PONG';}catch{/* bounded test startup */}if(ready)break;await delay(100);}
  if(!ready)throw Error('Regional test Redis startup failed');
  docker(['run','--rm','-i','--network',`container:${id}`,'--user','node','--read-only','--tmpfs','/run/ps024:rw,noexec,nosuid,mode=0700,uid=1000,gid=1000,size=1m','--cap-drop','ALL',
    '--security-opt','no-new-privileges','--memory','256m','--pids-limit','64','--log-driver','none',image],true,JSON.stringify(tls));
}finally{if(id)docker(['rm','-f',id]);}
