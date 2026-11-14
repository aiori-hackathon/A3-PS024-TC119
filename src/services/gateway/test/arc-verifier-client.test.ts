import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Socket } from 'node:net';
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import fixture from '../../../contracts/fixtures/regional-golden.json' with {type:'json'};
import params from '../../arc/fixtures/public-parameters.json' with {type:'json'};
import { canonicalJson, hex, sha256 } from '../../../contracts/lib/index.ts';
import { REGIONAL, arcRpcMacInput, encodeRegionalFrame, regionalPolicyDigest, validateRegionalPolicy, type ArcRequest } from '../../../contracts/lib/regional.ts';
import { checkRegionalMac, regionalMac } from '../../../contracts/lib/regional-wire.ts';
import { ArcVerifierClient } from '../src/arc-verifier-client.ts';

async function fixtureServer(t:any){
  const p=validateRegionalPolicy({...fixture.arc_policy,arc_key_id:params.arc_key_id}),key=randomBytes(32),sockets=new Set<Socket>();
  const bootstrap={contract_version:REGIONAL.contract_version,run_id:p.run_id,service_incarnation:'1'.repeat(32),
    arc_implementation_revision:p.arc_implementation_revision!,issuer_params_b64url:params.issuer_params_b64url,arc_key_id:p.arc_key_id!};
  let mode='verified',calls=0,faults=0;const seen:ArcRequest[]=[];
  // Fixture-backed HMAC peer: verifies transport, not a claim of live Rust ARC cryptography.
  const server=createServer(socket=>{
    sockets.add(socket);socket.on('close',()=>sockets.delete(socket));socket.on('error',()=>{});
    let data=Buffer.alloc(0);
    socket.on('data',chunk=>{
      data=Buffer.concat([data,chunk]);if(data.at(-1)!==10)return;
      const frame=JSON.parse(data.toString()) as {body:ArcRequest;mac:string},req=frame.body;
      assert.equal(req.operation,'verify');assert.equal(req.policy_digest,regionalPolicyDigest(p));
      assert.ok(checkRegionalMac(key,arcRpcMacInput('request','verify',req),frame.mac));
      seen.push(req);calls++;
      if(mode==='hang')return;
      const reply:any={contract_version:req.contract_version,run_id:req.run_id,policy_digest:req.policy_digest,
        request_id:req.request_id,service_incarnation:req.service_incarnation,operation:'verify',
        request_digest:hex(sha256(Buffer.from(canonicalJson(req)))),status:'verified',
        spend_tag_b64url:Buffer.from(params.issuer_params_b64url,'base64url').subarray(0,33).toString('base64url')};
      if(['invalid-proof','invalid-input','unavailable'].includes(mode)){delete reply.spend_tag_b64url;reply.status='refused';reply.code=mode;}
      if(mode==='wrong-request')reply.request_id='f'.repeat(32);
      if(mode==='wrong-incarnation')reply.service_incarnation='f'.repeat(32);
      const mac=mode==='bad-mac'?'0'.repeat(64):regionalMac(key,arcRpcMacInput('response','verify',reply));
      const wire=encodeRegionalFrame(reply,mac);
      socket.write(mode==='noncanonical'?Buffer.from(JSON.stringify({body:reply,mac},null,2)+'\n'):wire);
    });
  });
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));const port=(server.address() as {port:number}).port;
  const clients:ArcVerifierClient[]=[];
  const client=()=>{const c=ArcVerifierClient.prepare(p,bootstrap,{host:'127.0.0.1',port},key,1,()=>{faults++;});clients.push(c);return c;};
  t.after(async()=>{await Promise.all(clients.map(c=>c.close()));for(const s of sockets)s.destroy();await new Promise<void>(resolve=>server.close(()=>resolve()));});
  return {p,key,client,seen,mode:(m:string)=>{mode=m;},counts:()=>({calls,faults})};
}

test('real framed RPC authenticates and binds verified receipts once to their owning client',async t=>{
  const f=await fixtureServer(t),a=f.client(),b=f.client(),bytes=Uint8Array.of(1,2,3);
  const work=a.verify(bytes);bytes[0]=9;const result=await work;
  const received=f.seen[0]!;assert.ok(received.operation==='verify');
  assert.equal(received.presentation_b64url,'AQID');assert.equal(result.kind,'verified');
  if(result.kind!=='verified')throw Error();
  assert.equal(b.consume(result.receipt),null);
  const candidate=a.consume(result.receipt);assert.equal(candidate?.kind,'regional-claim-candidate');
  assert.equal(candidate?.not_after_ms,0);assert.equal(a.consume(result.receipt),null);assert.equal(a.consume({}),null);
});
test('ordinary invalid proofs refuse without faulting the run; unavailable service closes it',async t=>{
  const f=await fixtureServer(t),client=f.client();f.mode('invalid-proof');
  assert.deepEqual(await client.verify(Uint8Array.of(1)),{kind:'rejected'});assert.equal(client.status.closed,false);
  f.mode('invalid-input');assert.deepEqual(await client.verify(Uint8Array.of(1)),{kind:'rejected'});assert.equal(client.status.closed,false);
  f.mode('verified');assert.equal((await client.verify(Uint8Array.of(2))).kind,'verified');assert.equal(f.counts().faults,0);
  f.mode('unavailable');assert.deepEqual(await client.verify(Uint8Array.of(3)),{kind:'unavailable'});assert.equal(f.counts().faults,1);
});
test('bad MAC, swapped request/incarnation and noncanonical frames cannot authorize or retry',async t=>{
  const f=await fixtureServer(t);
  for(const mode of ['bad-mac','wrong-request','wrong-incarnation','noncanonical']){
    f.mode(mode);const c=f.client(),before=f.counts().calls;
    assert.deepEqual(await c.verify(Uint8Array.of(1)),{kind:'unavailable'});assert.equal(c.status.closed,true);
    assert.deepEqual(await c.verify(Uint8Array.of(1)),{kind:'unavailable'});assert.equal(f.counts().calls,before+1);
  }
});
test('caller deadline, cancellation and pool pressure are bounded without hidden retries',async t=>{
  const f=await fixtureServer(t);f.mode('hang');const c=f.client();
  const pending=c.verify(Uint8Array.of(1),{deadline_ms:performance.now()+200});
  assert.deepEqual(await c.verify(Uint8Array.of(2)),{kind:'busy'});
  assert.deepEqual(await pending,{kind:'unavailable'});assert.equal(f.counts().calls,1);
  const next=f.client(),abort=new AbortController();
  const canceled=next.verify(Uint8Array.of(1),{signal:abort.signal});abort.abort();
  assert.deepEqual(await canceled,{kind:'canceled'});assert.equal(next.status.closed,false);
  f.mode('verified');assert.equal((await next.verify(Uint8Array.of(2))).kind,'verified');
});
