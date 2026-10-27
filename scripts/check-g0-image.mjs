import {spawnSync} from 'node:child_process';
const image=process.argv[2]??'tokenforge-g0:local';
function docker(args,input) {
  const r=spawnSync('docker',args,{input,encoding:'utf8',shell:false,timeout:120000,maxBuffer:1024*1024});
  if(r.error||r.status!==0)throw Error('Docker G0 check failed: '+(r.stderr||r.error?.message||'nonzero exit'));
  return r.stdout.trim();
}
const config=JSON.parse(docker(['image','inspect',image]))[0].Config;
if(config.User!=='node'||config.ExposedPorts)throw Error('Image user/port boundary failed');
const restrictions=['--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','128m','--pids-limit','64'];
const smoke=JSON.parse(docker(['run',...restrictions,image]));
if(smoke.node_major!==24||smoke.contract_version!=='TF-PS024-1.0.0')throw Error('Bootstrap mismatch');
const script=`
import {readdirSync,readFileSync,existsSync} from 'node:fs';
import {publicVerif,TokenChallenge} from '@cloudflare/privacypass-ts';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
if(readdirSync('/app').some(p=>!['dist','node_modules'].includes(p)))throw Error('Unexpected app payload');
if(JSON.stringify(readdirSync('/app/dist').sort())!==JSON.stringify(['bootstrap.mjs','fixed-origin.mjs','flow-admission.mjs','http-auth.mjs','https-gateway.mjs','redis-adapter.mjs','replay-scripts.mjs','request-coordinator.mjs','token-verifier.mjs','worker-lease.mjs']))throw Error('Unexpected build payload');
const {HttpsGateway}=await import('/app/dist/https-gateway.mjs');
if(typeof HttpsGateway.prepare!=='function')throw Error('HTTPS gateway missing');
const {RequestCoordinator}=await import('/app/dist/request-coordinator.mjs');
if(typeof RequestCoordinator.prepare!=='function')throw Error('Coordinator missing');
const {FixedOrigin}=await import('/app/dist/fixed-origin.mjs');
if(typeof FixedOrigin.prepare!=='function')throw Error('Fixed origin missing');
const {FlowAdmission}=await import('/app/dist/flow-admission.mjs');
if(typeof FlowAdmission.prepare!=='function')throw Error('Flow admission missing');
const {WorkerLease}=await import('/app/dist/worker-lease.mjs');
if(typeof WorkerLease.prepare!=='function')throw Error('Worker lease missing');
for(let worker=0;worker<2;worker++) {
  const code="process.on('message',()=>process.send(process.hrtime.bigint().toString()));process.send('ready');";
  const child=spawn(process.execPath,['--input-type=module','-e',code],{stdio:['ignore','ignore','ignore','ipc']});
  try {
    const [ready]=await once(child,'message',{signal:AbortSignal.timeout(5000)});
    if(ready!=='ready')throw Error('Clock child not ready');
    const reply=once(child,'message',{signal:AbortSignal.timeout(5000)});
    const before=process.hrtime.bigint(); child.send('clock');
    const [value]=await reply; const after=process.hrtime.bigint();
    if(typeof value!=='string'||!/^(0|[1-9][0-9]*)$/.test(value)||value.length>20)throw Error('Clock format mismatch');
    const stamp=BigInt(value);
    if(stamp<before||stamp>after)throw Error('Supervisor and worker clock origins disagree');
  } finally {
    const exited=once(child,'exit',{signal:AbortSignal.timeout(5000)}); child.kill(); await exited;
  }
}
console.log(JSON.stringify({clock:'process.hrtime.bigint',same_container_children:2,bracketed:true}));
const {openRedisReplayStore}=await import('/app/dist/redis-adapter.mjs');
if(typeof openRedisReplayStore!=='function'||JSON.parse(readFileSync('/app/node_modules/ioredis/package.json','utf8')).version!=='6.0.0')throw Error('Pinned Redis adapter missing');
const {REPLAY_SCRIPTS}=await import('/app/dist/replay-scripts.mjs');
for(const script of Object.values(REPLAY_SCRIPTS))if(!/^[0-9a-f]{40}$/.test(script.sha1)||typeof script.source!=='string')throw Error('Replay scripts missing');
const {TokenVerifier}=await import('/app/dist/token-verifier.mjs');
if(typeof TokenVerifier.prepare!=='function')throw Error('Verification component missing');
const {parseAuthorization,GatewayResponses}=await import('/app/dist/http-auth.mjs');
if(parseAuthorization([]).kind!=='missing'||typeof GatewayResponses.prepare!=='function')throw Error('HTTP auth components missing');
for(const p of ['typescript','esbuild','ajv'])if(existsSync('/app/node_modules/'+p))throw Error('Dev tool in runtime');
if(JSON.parse(readFileSync('/app/node_modules/sjcl/package.json','utf8')).version!=='1.0.9')throw Error('Patch missing');
const {BlindRSAMode,Client,Issuer,Origin,getPublicKeyBytes}=publicVerif;
const mode=BlindRSAMode.PSS;
const keys=await Issuer.generateKey(mode,{modulusLength:2048,publicExponent:Uint8Array.of(1,0,1)});
const client=new Client(mode);
const request=await client.createTokenRequest(new TokenChallenge(2,'issuer.lab.test',new Uint8Array(32),['origin.lab.test']),await getPublicKeyBytes(keys.publicKey));
const response=await new Issuer(mode,'issuer.lab.test',keys.privateKey,keys.publicKey).issue(request);
const token=await client.finalize(response);
const verified=await new Origin(mode).verify(token,keys.publicKey);
if(!verified||request.serialize().length!==259||response.serialize().length!==256||token.serialize().length!==354)throw Error('Linux crypto mismatch');
console.log(JSON.stringify({platform:process.platform,node:process.versions.node,request_bytes:259,response_bytes:256,token_bytes:354,verified,runtime_payload:'production-only'}));
`;
console.log(docker(['run',...restrictions,'-i',image,'node','--input-type=module','-'],script));
console.log('PASS: non-root/no-network/read-only G0 image, minimal app payload and fresh Linux blind-issuance roundtrip.');
