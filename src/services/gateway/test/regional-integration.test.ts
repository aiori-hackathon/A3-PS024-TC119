import test,{type TestContext} from 'node:test';
import { connect,type Socket } from 'node:net';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { unlink } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomBytes, sign } from 'node:crypto';
import { createServer } from 'node:http';
import { request } from 'node:https';
import { Redis } from 'ioredis';
import { publicVerif, TokenChallenge } from '@cloudflare/privacypass-ts';
import { PROTOCOL, validateControlResponse, canonicalJson, configurationDigest, hex, sha256 } from '../../../contracts/lib/index.ts';
import { REGIONAL, holderProofInput, regionalPolicyDigest, validateRegionalPolicy, type RegionalProfile, type HolderNonce } from '../../../contracts/lib/regional.ts';
import { decodeCanonicalRegionalJson, validateRegionalPublicResponse } from '../../../contracts/lib/regional-wire.ts';
import { initializeStore, loadReplayScripts, parseRedisTime } from '../../../contracts/lib/replay.ts';
import { initializeRegionalStore, regionalGatewayAclArguments, verifyRegionalStoreReady } from '../../../contracts/lib/regional-replay.ts';
import { prepareRegionalGateway } from '../src/regional-gateway.ts';
import type { RegionalStartup } from '../src/regional-startup.ts';
import { WorkerLease } from '../src/worker-lease.ts';
import { holderKey, holderSetup } from './helpers/holder.ts';

const tls=JSON.parse(readFileSync(0,'utf8')) as {key:string;cert:string};

test('real TLS, genuine issuance, two regional pools and Redis preserve owner access and single origin arrival',async t=>{
  const admin=new Redis({host:'127.0.0.1',port:6379,lazyConnect:true,enableReadyCheck:false,disableClientInfo:true,retryStrategy:()=>null});
  admin.on('error',()=>{});await admin.connect();t.after(()=>admin.disconnect(false));
  const io={call:(command:string,...args:(string|number)[])=>admin.call(command,...args)};
  const setup=await holderSetup(parseRedisTime(await admin.time())-1000),{m,p}=setup,digest=configurationDigest(m);
  await loadReplayScripts(io);await initializeStore(io,m);await initializeRegionalStore(io,m,p);
  const password=randomBytes(32).toString('hex'),context=randomBytes(32),nonce=randomBytes(32);
  assert.equal(await io.call('ACL',...regionalGatewayAclArguments('tfr_gateway',password)),'OK');
  const restricted=new Redis({host:'127.0.0.1',port:6379,username:'tfr_gateway',password,lazyConnect:true,enableReadyCheck:false,
    disableClientInfo:true,retryStrategy:()=>null});restricted.on('error',()=>{});
  try{
    await restricted.connect();await verifyRegionalStoreReady({call:(command,...args)=>restricted.call(command,...args)},m,p);
    const probe=await admin.script('LOAD',"redis.call('HSET',KEYS[1],'blocked_probe','1');return 'BAD'");
    for(const key of ['pp:policy','tfr:policy']){
      let directDenied=false,scriptDenied=false;
      try{await restricted.hset(key,'blocked_probe','1');}catch{directDenied=true;}
      try{await restricted.call('EVALSHA',probe as string,1,key);}catch{scriptDenied=true;}
      assert.ok(directDenied&&scriptDenied,'policy writes must be denied both directly and inside an allowed script');
      assert.equal(await admin.hexists(key,'blocked_probe'),0);
    }
  }catch(error){
    const message=error instanceof Error?error.message:'';
    throw Error(message.includes('NOPERM')||message.includes('permissions')?'restricted-regional-readiness-permission-refused':'restricted-regional-readiness-failed');
  }finally{restricted.disconnect(false);}
  let arrivals=0;
  const origin=createServer((req,res)=>{
    arrivals++;
    assert.equal(req.method,'GET');assert.equal(req.url,'/resource');assert.equal(req.headers['x-tokenforge-run'],m.run_id);
    res.writeHead(200,{'content-length':'2'}).end('ok');
  });
  await new Promise<void>(resolve=>origin.listen(8080,'127.0.0.1',resolve));
  t.after(()=>new Promise<void>(resolve=>origin.close(()=>resolve())));
  const workers:Awaited<ReturnType<typeof prepareRegionalGateway>>[]=[],heartbeats:ReturnType<typeof setInterval>[]=[];
  t.after(async()=>{heartbeats.forEach(clearInterval);await Promise.all(workers.map(w=>w.gateway.close()));});
  const ports:number[]=[];
  for(let i=0;i<2;i++){
    const ids={worker_incarnation:String(i+1).repeat(32),supervisor_incarnation:'3'.repeat(32)},lease=WorkerLease.prepare(m,ids,()=>{});
    const worker=await prepareRegionalGateway(m,p,lease,{redis:{host:'127.0.0.1',port:6379,username:'tfr_gateway',password},tls,
      auth:{profile:'type2-holder',context_key:context,nonce_key:nonce}});workers.push(worker);
    let seq=0;const grant=()=>{const now=process.hrtime.bigint();return {version:1,run_id:m.run_id,config_digest:digest,...ids,sequence:seq,
      issued_at_ns:String(now),expires_at_ns:String(now+3000000000n)};};
    assert.ok(lease.enable(grant()));heartbeats.push(setInterval(()=>{seq++;lease.heartbeat(grant());},500));
    ports.push((await worker.gateway.listen('127.0.0.1',0)).port);
  }
  async function post(body:unknown,port:number,path='/regional/holder/redeem'):Promise<{status:number;body:Buffer}>{
    const bytes=Buffer.from(canonicalJson(body));
    return new Promise((resolve,reject)=>{
      const req=request({host:'127.0.0.1',port,servername:m.origin_name,ca:tls.cert,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',
        method:'POST',path,headers:{host:m.origin_name,'content-type':'application/json','content-length':bytes.length},agent:false},res=>{
        const chunks:Buffer[]=[];res.on('data',chunk=>chunks.push(chunk));
        res.once('end',()=>{try{const body=Buffer.concat(chunks);if(res.statusCode===200&&path!=='/regional/holder/redeem')decodeCanonicalRegionalJson(body);resolve({status:res.statusCode!,body});}catch(error){reject(error);}});res.once('error',reject);
      });req.once('error',reject);req.end(bytes);
    });
  }
  const redeem=async(body:unknown,port:number,path?:string)=>(await post(body,port,path)).status;
  const base={contract_version:REGIONAL.contract_version,policy_digest:regionalPolicyDigest(p)};
  async function issue(port:number){
    const owner=holderKey();
    const reply=await post({...base,public_key_spki_b64url:owner.spki},port,'/regional/holder/challenge');
    assert.equal(reply.status,200);const challenge=JSON.parse(reply.body.toString());
    validateRegionalPublicResponse('holder-challenge',challenge,p);
    const client=new publicVerif.Client(publicVerif.BlindRSAMode.PSS);
    const request=await client.createTokenRequest(TokenChallenge.deserialize(Uint8Array.from(Buffer.from(challenge.challenge_b64url,'base64url'))),setup.publicBytes);
    // Genuine issuance through a test-local issuer API, not the pending Mihir issuer/controller deployment.
    return {owner,token:Uint8Array.from((await client.finalize(await setup.issuer.issue(request))).serialize())};
  }
  async function proof(token:Uint8Array,owner:ReturnType<typeof holderKey>,port:number){
    const reply=await post({...base,token_hash:hex(sha256(token)),public_key_spki_b64url:owner.spki},port,'/regional/holder/nonce');
    assert.equal(reply.status,200);const signed=JSON.parse(reply.body.toString()) as {body:HolderNonce;mac:string};
    validateRegionalPublicResponse('holder-nonce',signed,p);
    const signature=sign('sha256',holderProofInput(p,token,owner.spki,signed,signed.body.issued_ms),{key:owner.privateKey,dsaEncoding:'ieee-p1363'});
    return {...base,token_b64url:Buffer.from(token).toString('base64url'),proof:{...base,public_key_spki_b64url:owner.spki,
      nonce:signed,signature_b64url:signature.toString('base64url')}};
  }
  const issued=await issue(ports[0]!);
  const attack=await proof(issued.token,holderKey(),ports[1]!);
  assert.equal(await redeem(attack,ports[0]!),403);assert.equal(arrivals,0);
  assert.equal(await admin.dbsize(),3);
  const owner=await proof(issued.token,issued.owner,ports[1]!);
  const changed=structuredClone(owner);changed.proof.nonce.mac='0'.repeat(64);
  assert.equal(await redeem(changed,ports[1]!),403);assert.equal(arrivals,0);
  assert.equal(await redeem(owner,ports[0]!,'/resource'),400);assert.equal(arrivals,0);
  assert.equal(await admin.dbsize(),3);
  assert.equal(await redeem(owner,ports[0]!),200);assert.equal(arrivals,1);
  assert.equal(await redeem(owner,ports[1]!),403);assert.equal(arrivals,1);
  const renewedNonce=await proof(issued.token,issued.owner,ports[0]!);
  assert.equal(await redeem(renewedNonce,ports[1]!),403);assert.equal(arrivals,1);
  const cross=await issue(ports[0]!),crossBody=await proof(cross.token,cross.owner,ports[0]!);
  assert.equal(await redeem(crossBody,ports[1]!),200);assert.equal(arrivals,2);
  const fresh=await issue(ports[1]!);
  const raced=await proof(fresh.token,fresh.owner,ports[0]!);
  const statuses=await Promise.all(Array.from({length:20},(_,i)=>redeem(raced,ports[i%2]!)));
  assert.equal(statuses.filter(s=>s===200).length,1);assert.equal(arrivals,3);assert.equal(await admin.dbsize(),6);
  assert.ok(statuses.every(s=>[200,403,503].includes(s)));
  assert.ok(workers.every(w=>w.coordinator.verificationAttempts>0));
  // Aggregate-only evidence; no tokens, proofs, keys or replay identities enter output.
  console.log('PASS: copied-token attacker refused; owner succeeds; 20-copy race adds exactly one origin arrival across two prepared pools.');
});

// Production serve.mjs -> private control -> two real OS workers sharing port 443.
// Each profile is a separate controller-reset experiment; no request selects a mode.
async function serving(t:TestContext,profile:RegionalProfile){
  const admin=new Redis({host:'127.0.0.1',port:6379,lazyConnect:true,enableReadyCheck:false,disableClientInfo:true,retryStrategy:()=>null});
  admin.on('error',()=>{});await admin.connect();t.after(()=>admin.disconnect(false));await admin.flushdb();
  const io={call:(command:string,...args:(string|number)[])=>admin.call(command,...args)};
  const f=await holderSetup(parseRedisTime(await admin.time())-1000),m=f.m;
  const p=validateRegionalPolicy({...f.p,profile,type2_key_id:profile==='ip'?null:m.token_key_id},m);
  await loadReplayScripts(io);await initializeStore(io,m);await initializeRegionalStore(io,m,p);
  const password=randomBytes(32).toString('hex');await io.call('ACL',...regionalGatewayAclArguments('tfr_process',password));
  let arrivals=0,mismatches=0;
  const origin=createServer((req,res)=>{
    arrivals++;
    if(req.method!=='GET'||req.url!=='/resource'||req.headers['x-tokenforge-run']!==m.run_id){mismatches++;res.writeHead(409).end();return;}
    res.writeHead(200,{'content-length':'2'}).end('ok');
  });await new Promise<void>(resolve=>origin.listen(8080,'127.0.0.1',resolve));
  const auth:RegionalStartup['auth']=profile==='ip'?{profile,source_key:randomBytes(32).toString('hex')}:
    profile==='type2-bearer'?{profile}:{profile:'type2-holder',context_key:randomBytes(32).toString('hex'),nonce_key:randomBytes(32).toString('hex')};
  const child=spawn(process.execPath,['dist/serve.mjs'],{stdio:['pipe','pipe','pipe']});
  const exited=new Promise<void>(resolve=>child.once('exit',()=>resolve()));child.stdout.resume();child.stderr.resume();
  child.stdin.end(JSON.stringify({listen_host:'127.0.0.1',tls,redis:{username:'tfr_process',password},regional:{policy:p,auth}}));
  let owner:Socket|undefined,heartbeat:ReturnType<typeof setInterval>|undefined;
  let knownWorkers:number[]=[];
  t.after(async()=>{
    clearInterval(heartbeat);if(child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');
    const timer=setTimeout(()=>child.kill('SIGKILL'),12000);await exited;clearTimeout(timer);owner?.destroy();
    origin.closeAllConnections();await new Promise<void>(resolve=>origin.close(()=>resolve()));
    await unlink(PROTOCOL.control_socket).catch(()=>{});
  });
  for(let n=0;n<150;n++){
    const socket=connect(PROTOCOL.control_socket);socket.on('error',()=>{});
    try{await once(socket,'connect');owner=socket;break;}catch{socket.destroy();if(child.exitCode!==null)throw Error('regional-process-start-failed');await delay(20);}
  }
  if(!owner)throw Error('regional-process-start-timeout');
  let carry='',incarnation:unknown=null,digest:unknown=null;
  const pending=new Map<string,(r:Record<string,any>)=>void>();
  owner.on('data',bytes=>{
    carry+=bytes.toString();let end:number;
    while((end=carry.indexOf('\n'))>=0){
      const r=JSON.parse(carry.slice(0,end));carry=carry.slice(end+1);validateControlResponse(r);
      pending.get(r.request_id)?.(r);pending.delete(r.request_id);
    }
  });
  let controlQueue=Promise.resolve();
  function call(command:string,payload:unknown={}):Promise<Record<string,any>>{
    const task=controlQueue.then(async()=>{
      const id=randomBytes(16).toString('hex');
      const response=await new Promise<Record<string,any>>((resolve,reject)=>{
        const timer=setTimeout(()=>{pending.delete(id);reject(Error('regional-control-timeout'));},8000);
        pending.set(id,r=>{clearTimeout(timer);resolve(r);});owner!.write(JSON.stringify({version:1,request_id:id,command,
          run_id:command==='STATUS'?null:m.run_id,config_digest:digest,target_incarnation:incarnation,payload})+'\n');
      });incarnation=response.incarnation;digest=response.config_digest;return response;
    });controlQueue=task.then(()=>{},()=>{});return task;
  }
  assert.equal((await call('STATUS')).state,'FENCED');
  assert.equal((await call('PREPARE_RUN',{manifest:m,proposed_config_digest:configurationDigest(m),role:'gateway',role_config:{}})).result,'PREPARED');
  knownWorkers=readFileSync(`/proc/${child.pid}/task/${child.pid}/children`,'utf8').trim().split(/\s+/).filter(Boolean).map(Number);
  assert.equal(knownWorkers.length,2);assert.notEqual(knownWorkers[0],knownWorkers[1]);
  assert.equal((await call('CHECK_READY')).result,'READY');assert.equal((await call('ENABLE')).result,'ENABLED');
  let sequence=0;
  heartbeat=setInterval(()=>{void call('HEARTBEAT',{seq:++sequence}).then(r=>assert.equal(r.result,'HEARTBEAT_ACK'));},500);
  function requestResource(path='/resource',body?:unknown,headers:Record<string,string>={}){
    const bytes=body===undefined?undefined:Buffer.from(canonicalJson(body));
    return new Promise<{status:number;body:Buffer;challenge:string|undefined}>((resolve,reject)=>{
      const req=request({host:'127.0.0.1',port:443,servername:m.origin_name,ca:tls.cert,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',agent:false,
        method:bytes?'POST':'GET',path,headers:{host:m.origin_name,...(bytes?{'content-type':'application/json','content-length':String(bytes.length)}:{}),...headers}},res=>{
        const chunks:Buffer[]=[];res.on('data',chunk=>chunks.push(chunk));res.on('error',reject);
        res.once('end',()=>resolve({status:res.statusCode!,body:Buffer.concat(chunks),challenge:res.headers['www-authenticate']}));
      });req.setTimeout(6000,()=>req.destroy());req.on('error',reject);req.end(bytes);
    });
  }
  return {f,m,p,admin,call,requestResource,arrivals:()=>arrivals,mismatches:()=>mismatches,
    async fence(){clearInterval(heartbeat);assert.equal((await call('FENCE',{reason:'test-cleanup'})).result,'FENCED');
      for(const pid of knownWorkers)assert.throws(()=>process.kill(pid,0));}};
}

test('production IP run enforces one 25-use TCP-source budget across two OS workers despite spoofed forwarding headers',async t=>{
  const s=await serving(t,'ip');
  assert.equal((await s.requestResource('/other')).status,400);assert.equal(s.arrivals(),0);assert.equal(await s.admin.dbsize(),3);
  for(let i=0;i<24;i++)assert.equal((await s.requestResource('/resource',undefined,{'x-forwarded-for':`192.0.2.${i+1}`,forwarded:`for=192.0.2.${i+1}`})).status,200);
  const race=await Promise.all(Array.from({length:20},(_,i)=>s.requestResource('/resource',undefined,{'x-forwarded-for':`198.51.100.${i+1}`})));
  assert.equal(race.filter(r=>r.status===200).length,1);assert.ok(race.every(r=>[200,429,503].includes(r.status)));
  assert.equal((await s.requestResource()).status,429);assert.equal(s.arrivals(),25);assert.equal(s.mismatches(),0);
  const r=await s.call('REPORT');assert.equal(r.result,'REPORT');assert.equal(r.data.counters.claims_successful,25);
  assert.equal(r.data.same_source_observed,true);assert.ok(r.data.worker_verification_attempts.every((w:any)=>w.attempts>0));
  assert.equal(r.data.origin_counts_available,false);assert.equal(await s.admin.dbsize(),4);
  // Lost authoritative state fences the whole generation; it must never recreate budget or fall back.
  await s.admin.del('tfr:policy');
  try{assert.equal((await s.requestResource()).status,503);}catch(error){if(error instanceof assert.AssertionError)throw error;}
  assert.equal(s.arrivals(),25);assert.equal(await s.admin.exists('tfr:policy'),0);await s.fence();
  await assert.rejects(s.requestResource());assert.equal(s.arrivals(),25);
  console.log('PASS: true two-worker IP boundary 25/26; spoofed forwarding identities cannot refill; FENCE removes listeners.');
});

test('production ordinary Type2 run challenges, verifies context and refuses copied-token replays across OS workers',async t=>{
  const s=await serving(t,'type2-bearer');const first=await s.requestResource();assert.equal(first.status,401);
  const encoded=/challenge="([^"]+)"/.exec(first.challenge!)![1]!;
  const client=new publicVerif.Client(publicVerif.BlindRSAMode.PSS);
  const req=await client.createTokenRequest(TokenChallenge.deserialize(Uint8Array.from(Buffer.from(encoded,'base64url'))),s.f.publicBytes);
  const token=Buffer.from((await client.finalize(await s.f.issuer.issue(req))).serialize()).toString('base64url');
  const headers={authorization:`PrivateToken token="${token}"`};
  const results=await Promise.all(Array.from({length:20},()=>s.requestResource('/resource',undefined,headers)));
  assert.equal(results.filter(r=>r.status===200).length,1);assert.equal(s.arrivals(),1);assert.equal(s.mismatches(),0);
  assert.equal((await s.requestResource('/resource',undefined,headers)).status,403);
  const r=await s.call('REPORT');assert.equal(r.data.counters.claims_successful,1);assert.ok(r.data.worker_verification_attempts.every((w:any)=>w.attempts>0));
  await s.fence();console.log('PASS: regional Type2 challenge and copied-token single spend through two OS workers; admission quotas not tested.');
});

test('production holder run refuses stolen token before owner success and cross-worker replay',async t=>{
  const s=await serving(t,'type2-holder'),owner=holderKey();
  const base={contract_version:REGIONAL.contract_version,policy_digest:regionalPolicyDigest(s.p)};
  const challenge=await s.requestResource('/regional/holder/challenge',{...base,public_key_spki_b64url:owner.spki});assert.equal(challenge.status,200);
  const client=new publicVerif.Client(publicVerif.BlindRSAMode.PSS);
  const req=await client.createTokenRequest(TokenChallenge.deserialize(Uint8Array.from(Buffer.from(JSON.parse(challenge.body.toString()).challenge_b64url,'base64url'))),s.f.publicBytes);
  const token=Uint8Array.from((await client.finalize(await s.f.issuer.issue(req))).serialize());
  async function proof(key:ReturnType<typeof holderKey>){
    const result=await s.requestResource('/regional/holder/nonce',{...base,token_hash:hex(sha256(token)),public_key_spki_b64url:key.spki});assert.equal(result.status,200);
    const nonce=JSON.parse(result.body.toString()) as {body:HolderNonce;mac:string};
    const signature=sign('sha256',holderProofInput(s.p,token,key.spki,nonce,nonce.body.issued_ms),{key:key.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
    return {...base,token_b64url:Buffer.from(token).toString('base64url'),proof:{...base,public_key_spki_b64url:key.spki,nonce,signature_b64url:signature}};
  }
  const attack=await proof(holderKey());assert.equal((await s.requestResource('/regional/holder/redeem',attack)).status,403);
  assert.equal(s.arrivals(),0);assert.equal(await s.admin.dbsize(),3);
  const valid=await proof(owner);assert.equal((await s.requestResource('/regional/arc/redeem',valid)).status,400);assert.equal(s.arrivals(),0);
  assert.equal((await s.requestResource('/regional/holder/redeem',valid)).status,200);assert.equal(s.arrivals(),1);
  const raced=await Promise.all(Array.from({length:20},()=>s.requestResource('/regional/holder/redeem',valid)));
  assert.ok(raced.every(r=>[403,503].includes(r.status)));assert.equal(s.arrivals(),1);assert.equal(s.mismatches(),0);
  const r=await s.call('REPORT');assert.equal(r.data.counters.claims_successful,1);assert.ok(r.data.worker_verification_attempts.every((w:any)=>w.attempts>0));
  await s.fence();console.log('PASS: stolen token refusal leaves owner usable; two production workers reject replay and cross-profile routes.');
});
