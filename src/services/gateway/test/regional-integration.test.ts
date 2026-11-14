import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomBytes, sign } from 'node:crypto';
import { createServer } from 'node:http';
import { request } from 'node:https';
import { Redis } from 'ioredis';
import { publicVerif, TokenChallenge } from '@cloudflare/privacypass-ts';
import { canonicalJson, configurationDigest, hex, sha256 } from '../../../contracts/lib/index.ts';
import { REGIONAL, holderProofInput, regionalPolicyDigest, type HolderNonce } from '../../../contracts/lib/regional.ts';
import { validateRegionalPublicResponse } from '../../../contracts/lib/regional-wire.ts';
import { initializeStore, loadReplayScripts, parseRedisTime } from '../../../contracts/lib/replay.ts';
import { initializeRegionalStore, regionalGatewayAclArguments, verifyRegionalStoreReady } from '../../../contracts/lib/regional-replay.ts';
import { prepareRegionalGateway } from '../src/regional-gateway.ts';
import { WorkerLease } from '../src/worker-lease.ts';
import { holderKey, holderSetup } from './helpers/holder.ts';

test('real TLS, genuine issuance, two regional pools and Redis preserve owner access and single origin arrival',async t=>{
  const tls=JSON.parse(readFileSync(0,'utf8')) as {key:string;cert:string};
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
        res.once('end',()=>resolve({status:res.statusCode!,body:Buffer.concat(chunks)}));res.once('error',reject);
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
