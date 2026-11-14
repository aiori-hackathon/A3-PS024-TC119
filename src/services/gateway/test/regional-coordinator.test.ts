import test from 'node:test';
import assert from 'node:assert/strict';
import fixture from '../../../contracts/fixtures/policy-golden.json' with {type:'json'};
import { canonicalJson, configurationDigest, validateManifest } from '../../../contracts/lib/index.ts';
import { REGIONAL, regionalPolicyDigest, validateRegionalPolicy } from '../../../contracts/lib/regional.ts';
import { RegionalCoordinator, type RegionalProofVerifier } from '../src/regional-coordinator.ts';
import { WorkerLease } from '../src/worker-lease.ts';
import type { RequestView, CoordinatorResponse } from '../src/request-coordinator.ts';
import type { RegionalReplayClaim } from '../src/regional-replay-store.ts';

function setup(){
  const m=validateManifest(fixture.manifest),digest=configurationDigest(m);
  const p=validateRegionalPolicy({contract_version:REGIONAL.contract_version,schema_version:1,run_id:m.run_id,baseline_config_digest:digest,
    profile:'arc',window_start_ms:m.run_start_ms,window_end_ms:m.run_start_ms+60000,quota:5,admitted_entitlements:5,
    resource_id:REGIONAL.resource_id,method:REGIONAL.method,url:REGIONAL.url,type2_key_id:null,arc_key_id:'a'.repeat(64),
    arc_implementation_revision:'b'.repeat(40),arc_tag_encoding:REGIONAL.arc_tag_encoding},m);
  const ids={worker_incarnation:'1'.repeat(32),supervisor_incarnation:'2'.repeat(32)},lease=WorkerLease.prepare(m,ids,()=>{});
  const abort=new AbortController(),events:string[]=[],spent=new Set<string>(),receipts=new WeakSet<object>();
  let rejected=false,unsafe=false,stopped=false,forwards=0;
  const replay={binding:{run_id:m.run_id,policy_digest:regionalPolicyDigest(p),profile:p.profile},signal:abort.signal,
    get status(){return {state:stopped?'closed' as const:'ready' as const,fault:null};},
    async snapshot(){events.push('snapshot');return {kind:'snapshot' as const,now_ms:m.run_start_ms+100};},
    async claim(candidate:any):Promise<RegionalReplayClaim>{
      events.push('claim');if(unsafe)return {kind:'unavailable'};
      if(spent.has(candidate.spend_id))return {kind:'rejected',reason:'already-spent'};
      spent.add(candidate.spend_id);return {kind:'claimed',expiry_ms:p.window_end_ms+30000};
    },close(){stopped=true;abort.abort();}};
  const origin={binding:{run_id:m.run_id,config_digest:digest},status:{closed:false,active:0,sockets:0,idle:0,queued:0},
    async forwardAfterClaim(){events.push('origin');forwards++;return {kind:'response' as const,status:200 as const,headers:{'content-length':'2'},body:Uint8Array.of(111,107)};},async close(){}};
  const verifier:RegionalProofVerifier={binding:{run_id:m.run_id,policy_digest:regionalPolicyDigest(p)},status:{closed:false},
    async verifyRequest(){events.push('verify');if(rejected)return {kind:'rejected'};const receipt=Object.freeze({});receipts.add(receipt);return {kind:'verified',receipt};},
    consume(receipt){events.push('consume');if(!receipts.delete(receipt))return null;return {kind:'regional-claim-candidate',spend_id:'c'.repeat(64),not_after_ms:0};},async close(){}};
  const coordinator=RegionalCoordinator.prepare(m,p,lease,replay,origin,verifier);
  const issued=process.hrtime.bigint();lease.enable({version:1,run_id:m.run_id,config_digest:digest,...ids,sequence:0,
    issued_at_ns:String(issued),expires_at_ns:String(issued+3000000000n)});
  const body=Buffer.from(canonicalJson({contract_version:REGIONAL.contract_version,policy_digest:regionalPolicyDigest(p),presentation_b64url:'AQID'}));
  const view=():RequestView=>({method:'POST',target:'/regional/arc/redeem',rawHeaders:['Host',m.origin_name,'Content-Type','application/json','Content-Length',String(body.length)],
    hasBody:true,body,signal:new AbortController().signal});
  const run=async(change:Partial<RequestView>={})=>{const out:CoordinatorResponse[]=[];await coordinator.handle({...view(),...change},async response=>{out.push(response);});return out[0];};
  return {coordinator,lease,events,run,body,view,spent,counts:()=>forwards,reject:(value:boolean)=>{rejected=value;},unsafe:()=>{unsafe=true;}};
}
test('regional coordinator verifies, refreshes authoritative time, consumes once, claims, then forwards',async()=>{
  const f=setup();try{
    assert.equal((await f.run())?.status,200);
    assert.deepEqual(f.events,['snapshot','verify','snapshot','consume','claim','origin']);
    assert.equal((await f.run())?.status,403);assert.equal(f.counts(),1);
  }finally{await f.coordinator.close();}
});
test('invalid proof and wrong route/authority/JSON consume no allowance; valid owner request remains usable',async()=>{
  const f=setup();try{
    f.reject(true);assert.equal((await f.run())?.status,403);assert.equal(f.spent.size,0);
    assert.equal((await f.run({target:'/resource',method:'GET'}))?.status,400);
    assert.equal((await f.run({body:Buffer.from('{}')}))?.status,400);
    assert.equal((await f.run({rawHeaders:['Host','attacker.example']}))?.status,400);
    assert.equal(f.spent.size,0);assert.equal(f.counts(),0);
    f.reject(false);assert.equal((await f.run())?.status,200);assert.equal(f.spent.size,1);
  }finally{await f.coordinator.close();}
});
test('uncertain claim closes admission without origin retry or delivery',async()=>{
  const f=setup();f.unsafe();
  await f.run();assert.equal(f.counts(),0);assert.equal(f.lease.status.run_closed,true);
  await f.run();assert.equal(f.counts(),0);await f.coordinator.close();
});
