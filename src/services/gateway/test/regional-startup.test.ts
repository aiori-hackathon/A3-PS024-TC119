import test from 'node:test';
import assert from 'node:assert/strict';
import { publicVerif, TokenChallenge } from '@cloudflare/privacypass-ts';
import { configurationDigest, encodeBase64Url } from '../../../contracts/lib/index.ts';
import { regionalContext, validateRegionalPolicy } from '../../../contracts/lib/regional.ts';
import { regionalType2Challenge } from '../../../contracts/lib/regional-wire.ts';
import { validateRegionalStartup } from '../src/regional-startup.ts';
import { ComparisonVerifier } from '../src/comparison-verifier.ts';
import { RegionalCoordinator } from '../src/regional-coordinator.ts';
import { WorkerLease } from '../src/worker-lease.ts';
import { holderSetup } from './helpers/holder.ts';

test('private startup owns its inputs and rejects profile/key/extra-field substitution',async()=>{
  const {p}=await holderSetup();
  const input={policy:structuredClone(p),auth:{profile:'type2-holder',context_key:'1'.repeat(64),nonce_key:'2'.repeat(64)}};
  const prepared=validateRegionalStartup(input);input.auth.nonce_key='3'.repeat(64);
  assert.equal(prepared.auth.profile,'type2-holder');
  if(prepared.auth.profile==='type2-holder')assert.equal(prepared.auth.nonce_key,'2'.repeat(64));
  for(const auth of [{...input.auth,nonce_key:input.auth.context_key},{...input.auth,extra:true},
    {...input.auth,profile:'arc'},{...input.auth,nonce_key:'bad'}])assert.throws(()=>validateRegionalStartup({...input,auth}));
  assert.throws(()=>validateRegionalStartup({...input,mode:'ip'}));
  assert.throws(()=>validateRegionalStartup({...input,auth:null}));
});

test('IP identity normalizes mapped IPv4, is policy-scoped, and owns the run key',async()=>{
  const {m,p:holder}=await holderSetup(),p=validateRegionalPolicy({...holder,profile:'ip',type2_key_id:null},m),key=Buffer.alloc(32,7);
  const a=await ComparisonVerifier.prepare(m,p,key),b=await ComparisonVerifier.prepare(m,p,key);key.fill(0);
  const candidate=async(v:ComparisonVerifier,address:unknown)=>{
    const result=await v.verifyRequest({remote_address:address},p.window_start_ms+1);
    assert.equal(result.kind,'verified');if(result.kind!=='verified')throw Error();
    const c=v.consume(result.receipt);assert.equal(v.consume(result.receipt),null);return c;
  };
  assert.deepEqual(await candidate(a,'127.0.0.1'),await candidate(b,'::ffff:127.0.0.1'));
  assert.notDeepEqual(await candidate(a,'127.0.0.1'),await candidate(b,'127.0.0.2'));
  assert.equal((await a.verifyRequest({remote_address:'forged'},p.window_start_ms+1)).kind,'rejected');
  assert.equal((await a.verifyRequest({},p.window_start_ms+1)).kind,'rejected');
  await a.close();assert.equal((await a.verifyRequest({remote_address:'127.0.0.1'},p.window_start_ms+1)).kind,'unavailable');await b.close();
});

test('ordinary Type2 accepts the regional challenge only and issues one-instance receipts',async()=>{
  const f=await holderSetup(),{m}=f,p=validateRegionalPolicy({...f.p,profile:'type2-bearer'},m);
  const a=await ComparisonVerifier.prepare(m,p),b=await ComparisonVerifier.prepare(m,p);
  const client=new publicVerif.Client(publicVerif.BlindRSAMode.PSS);
  const req=await client.createTokenRequest(TokenChallenge.deserialize(regionalType2Challenge(regionalContext(p))),f.publicBytes);
  const token=(await client.finalize(await f.issuer.issue(req))).serialize();
  const result=await a.verifyRequest({token_b64url:encodeBase64Url(token,false)},p.window_start_ms+1);
  assert.equal(result.kind,'verified');if(result.kind!=='verified')throw Error();
  assert.equal(b.consume(result.receipt),null);assert.ok(a.consume(result.receipt));assert.equal(a.consume(result.receipt),null);
  const other=validateRegionalPolicy({...p,window_start_ms:p.window_start_ms+1,window_end_ms:p.window_end_ms+1,
    baseline_config_digest:configurationDigest(m)});
  const wrong=await ComparisonVerifier.prepare(m,other);
  assert.equal((await wrong.verifyRequest({token_b64url:encodeBase64Url(token,false)},other.window_start_ms+1)).kind,'rejected');
  assert.equal((await b.verifyRequest({token_b64url:encodeBase64Url(token,false)},p.window_end_ms)).kind,'rejected');
  await Promise.all([a.close(),b.close(),wrong.close()]);
});

test('coordinator captures TCP source and headers before asynchronous admission',async()=>{
  const {m,p:holder}=await holderSetup(),p=validateRegionalPolicy({...holder,profile:'ip',type2_key_id:null},m);
  const key=Buffer.alloc(32,8),verifier=await ComparisonVerifier.prepare(m,p,key),reference=await ComparisonVerifier.prepare(m,p,key);
  const ids={worker_incarnation:'1'.repeat(32),supervisor_incarnation:'2'.repeat(32)},digest=configurationDigest(m);
  const lease=WorkerLease.prepare(m,ids,()=>{}),abort=new AbortController();let spent:unknown;
  const replay={binding:{...verifier.binding,profile:p.profile},status:{state:'ready' as const,fault:null},signal:abort.signal,
    async snapshot(){return {kind:'snapshot' as const,now_ms:p.window_start_ms+1};},
    async claim(candidate:unknown){spent=candidate;return {kind:'claimed' as const,expiry_ms:p.window_end_ms+30000};},close(){abort.abort();}};
  const origin={binding:{run_id:m.run_id,config_digest:digest},status:{closed:false,active:0,sockets:0,idle:0,queued:0},
    async forwardAfterClaim(){return {kind:'response' as const,status:200 as const,headers:{'content-length':'2'},body:Uint8Array.of(111,107)};},async close(){}};
  const coordinator=RegionalCoordinator.prepare(m,p,lease,replay,origin,verifier),now=process.hrtime.bigint();
  assert.ok(lease.enable({version:1,run_id:m.run_id,config_digest:digest,...ids,sequence:0,issued_at_ns:String(now),expires_at_ns:String(now+3000000000n)}));
  try{
    const view={method:'GET',target:'/resource',rawHeaders:['Host',m.origin_name],hasBody:false,remoteAddress:'127.0.0.1',signal:new AbortController().signal};
    let status=0;const work=coordinator.handle(view,async response=>{status=response.status;});
    view.remoteAddress='127.0.0.2';view.rawHeaders[1]='attacker.example';await work;assert.equal(status,200);
    const expected=await reference.verifyRequest({remote_address:'127.0.0.1'},p.window_start_ms+1);
    assert.equal(expected.kind,'verified');if(expected.kind!=='verified')throw Error();assert.deepEqual(spent,reference.consume(expected.receipt));
  }finally{await coordinator.close();await reference.close();}
});
