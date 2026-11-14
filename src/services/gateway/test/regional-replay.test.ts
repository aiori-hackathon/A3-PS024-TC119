import test from 'node:test';
import assert from 'node:assert/strict';
import golden from '../../../contracts/fixtures/policy-golden.json' with {type:'json'};
import { configurationDigest, makeManifest, type Manifest } from '../../../contracts/lib/index.ts';
import { REPLAY_SCRIPTS } from '../../../contracts/lib/replay.ts';
import { REGIONAL, regionalPolicyDigest, validateRegionalPolicy, type RegionalPolicy } from '../../../contracts/lib/regional.ts';
import { regionalStoreState, regionalClaimCommand, parseRegionalClaim, parseRegionalSnapshot,
  REGIONAL_REPLAY_SCRIPTS, REGIONAL_GATEWAY_ACL_RULES, regionalGatewayAclArguments } from '../../../contracts/lib/regional-replay.ts';
import { RegionalReplayStore } from '../src/regional-replay-store.ts';
import type { ReplayConnection, ReplayFault } from '../src/replay-store.ts';

function setup(profile:'arc'|'type2-holder'='arc',gateway:'B0'|'B1'='B1'){
  const m=makeManifest({run_id:golden.manifest.run_id,run_start_ms:golden.manifest.run_start_ms,
    token_key_spki_b64url:golden.manifest.token_key_spki_b64url,gateway_profile:gateway,
    snapshot_script_sha1:REPLAY_SCRIPTS.snapshot.sha1,claim_script_sha1:REPLAY_SCRIPTS.claim.sha1});
  const p=validateRegionalPolicy({contract_version:REGIONAL.contract_version,schema_version:1,run_id:m.run_id,
    baseline_config_digest:configurationDigest(m),profile,window_start_ms:m.run_start_ms,window_end_ms:m.run_start_ms+60000,
    quota:5,admitted_entitlements:5,resource_id:REGIONAL.resource_id,method:REGIONAL.method,url:REGIONAL.url,
    type2_key_id:profile==='type2-holder'?m.token_key_id:null,arc_key_id:profile==='arc'?'a'.repeat(64):null,
    arc_implementation_revision:profile==='arc'?'b'.repeat(40):null,arc_tag_encoding:profile==='arc'?REGIONAL.arc_tag_encoding:null},m);
  return {m,p};
}
class Connection implements ReplayConnection{
  calls:{command:string;args:(string|number)[]}[]=[];closed=0;connected=0;loss=()=>{};
  intercept:((command:string,args:(string|number)[])=>unknown)|undefined;
  readonly m:Manifest;readonly p:RegionalPolicy;
  constructor(m:Manifest,p:RegionalPolicy){this.m=m;this.p=p;}
  async connect(){this.connected++;}
  close(){this.closed++;}
  onLoss(fn:()=>void){this.loss=fn;}
  async call(command:string,...args:(string|number)[]):Promise<unknown>{
    this.calls.push({command,args});return this.intercept?this.intercept(command,args):this.normal(command,args);
  }
  normal(command:string,args:(string|number)[]):unknown{
    if(command==='SCRIPT')return [1,1];
    if(command==='TYPE')return 'hash';if(command==='PTTL')return -1;if(command==='HLEN')return 7;
    if(command==='HMGET'){const state=regionalStoreState(this.m,this.p);return args.slice(1).map(k=>state[String(k)]);}
    if(command==='EVALSHA')return args[0]===REGIONAL_REPLAY_SCRIPTS.snapshot.sha1?
      ['REGIONAL_SNAPSHOT',this.m.run_id,regionalPolicyDigest(this.p),this.p.window_start_ms+100,this.p.window_start_ms,this.p.window_end_ms]:
      ['CLAIMED',this.p.window_end_ms+30000];
    throw Error('unexpected private transport operation');
  }
}
async function fixture(profile:'arc'|'type2-holder'='arc',gateway:'B0'|'B1'='B1'){
  const {m,p}=setup(profile,gateway),connections=Array.from({length:m.limits.gateway.redis_connections_per_worker},()=>new Connection(m,p));
  const faults:ReplayFault[]=[];
  const store=await RegionalReplayStore.prepare(m,p,connections,f=>faults.push(f));
  return {m,p,connections,faults,store};
}
const candidate=(notAfter=0)=>({kind:'regional-claim-candidate',spend_id:'c'.repeat(64),not_after_ms:notAfter});
const deferred=()=>{let resolve!:(v:unknown)=>void;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};

test('regional readiness and claims use immutable policy, separate script and policy-scoped spent key',async()=>{
  const {m,p,connections,store}=await fixture();
  assert.deepEqual(await store.snapshot(),{kind:'snapshot',now_ms:p.window_start_ms+100});
  const c=candidate();const work=store.claim(c);c.spend_id='d'.repeat(64);
  assert.deepEqual(await work,{kind:'claimed',expiry_ms:p.window_end_ms+30000});
  const call=connections.flatMap(c=>c.calls).find(c=>c.command==='EVALSHA'&&c.args[0]===REGIONAL_REPLAY_SCRIPTS.claim.sha1)!;
  assert.deepEqual([call.command,...call.args],regionalClaimCommand(m,p,'c'.repeat(64),0));
  assert.match(String(call.args[5]),/^tfr:spent:/);
  store.close();assert.equal(store.signal.aborted,true);
});

test('ordinary expiry/replay refusals preserve readiness; unsafe state closes every connection once',async()=>{
  const {p,store,connections,faults}=await fixture('type2-holder');
  for(const [tag,reason] of [['WINDOW_CLOSED','window-closed'],['NONCE_EXPIRED','nonce-expired'],['ALREADY_SPENT','already-spent']] as const){
    connections.forEach(c=>{c.intercept=()=>[tag];});
    assert.deepEqual(await store.claim(candidate(p.window_start_ms+10000)),{kind:'rejected',reason});
    assert.equal(store.status.state,'ready');
  }
  connections.forEach(c=>{c.intercept=()=>['CLOCK_UNSAFE'];});
  assert.deepEqual(await store.claim(candidate(p.window_end_ms)),{kind:'unavailable'});
  assert.deepEqual(faults,['clock-unsafe']);assert.ok(connections.every(c=>c.closed===1));
  const calls=connections.reduce((n,c)=>n+c.calls.length,0);
  assert.deepEqual(await store.snapshot(),{kind:'unavailable'});
  assert.equal(connections.reduce((n,c)=>n+c.calls.length,0),calls);
});

test('invalid internal candidates never invoke Redis and cannot supply an alternate window or nonce mode',async()=>{
  for(const bad of [{...candidate(),extra:true},{...candidate(),spend_id:'bad'},candidate(-0),candidate(1),{...candidate(),not_after_ms:'0'}]){
    const {store,connections}=await fixture();const before=connections.reduce((n,c)=>n+c.calls.length,0);
    assert.deepEqual(await store.claim(bad),{kind:'unavailable'});
    assert.equal(connections.reduce((n,c)=>n+c.calls.length,0),before);assert.equal(store.status.state,'closed');
  }
});

test('bounded slots refuse excess without hidden queues; loss suppresses pending successful replies',async()=>{
  const {store,connections,faults}=await fixture();const pending=connections.map(()=>deferred());
  connections.forEach((c,i)=>{c.intercept=()=>pending[i]!.promise;});
  const one=store.claim(candidate()),two=store.claim({...candidate(),spend_id:'e'.repeat(64)});
  assert.deepEqual(await store.claim(candidate()),{kind:'busy'});
  connections[0]!.loss();pending.forEach(p=>p.resolve(['CLAIMED',setup().p.window_end_ms+30000]));
  assert.deepEqual(await one,{kind:'unavailable'});assert.deepEqual(await two,{kind:'unavailable'});
  assert.deepEqual(faults,['dependency-lost']);assert.ok(connections.every(c=>c.closed===1));
});

test('transport uncertainty is terminal, bounded and never retried',async()=>{
  const {store,connections,faults}=await fixture('arc','B0');
  const c=connections[0]!;const before=c.calls.length;
  c.intercept=()=>new Promise(()=>{});
  assert.deepEqual(await store.claim(candidate()),{kind:'unavailable'});
  assert.deepEqual(faults,['dependency-lost']);assert.equal(c.calls.length,before+1);assert.equal(c.closed,1);
  assert.deepEqual(await store.claim(candidate()),{kind:'unavailable'});assert.equal(c.calls.length,before+1);
  assert.deepEqual(store.rpcOutcomes.find(r=>r.operation==='claim'),{operation:'claim',failures:1,timeouts:1,uncertain:1});
  const metric=store.measurements.find(m=>m.metric==='claim_rpc_ms')!;assert.equal(metric.count,0);assert.equal(metric.failures,1);
});

test('readiness rejects altered policy, missing script and duplicate connections without repair',async()=>{
  const {m,p}=setup();
  for(const defect of ['policy','scripts','snapshot']){
    const connections=[new Connection(m,p),new Connection(m,p)];
    connections.forEach(c=>{c.intercept=(command,args)=>{
      if(defect==='policy'&&command==='HMGET')return ['wrong'];
      if(defect==='scripts'&&command==='SCRIPT')return [1,0];
      if(defect==='snapshot'&&command==='EVALSHA')return ['REGIONAL_SNAPSHOT',m.run_id,'0'.repeat(64),p.window_start_ms,p.window_start_ms,p.window_end_ms];
      return c.normal(command,args);
    };});
    await assert.rejects(()=>RegionalReplayStore.prepare(m,p,connections,()=>{}),/regional-replay-preparation/);
    assert.ok(connections.every(c=>c.closed>0));
    assert.ok(connections.every(c=>c.calls.every(call=>!['SET','HSET','SCRIPT LOAD'].includes(call.command))));
  }
  const c=new Connection(m,p);
  await assert.rejects(()=>RegionalReplayStore.prepare(m,p,[c,c],()=>{}),/regional-replay-configuration/);
});

test('reply parsing and separate ACL reject truthy, mistimed or administrative capabilities',()=>{
  const {m,p}=setup();
  for(const reply of [['CLAIMED'],['CLAIMED',String(p.window_end_ms+30000)],['CLAIMED',p.window_end_ms+30001],true,['NONCE_EXPIRED'],['ALREADY_SPENT','extra']])
    assert.throws(()=>parseRegionalClaim(reply,m,p));
  assert.throws(()=>parseRegionalSnapshot(['REGIONAL_SNAPSHOT',m.run_id,regionalPolicyDigest(p),p.window_end_ms,p.window_start_ms,p.window_end_ms],m,p));
  assert.equal(REGIONAL_GATEWAY_ACL_RULES.some(r=>r.includes('pp:spent')),false);
  assert.ok(!REGIONAL_GATEWAY_ACL_RULES.includes('+evalsha'));
  assert.ok(REGIONAL_GATEWAY_ACL_RULES.some(r=>r.startsWith('(+evalsha ')));
  for(const forbidden of ['+script|load','+eval','+acl','+config','+flushdb','+del'])assert.ok(!REGIONAL_GATEWAY_ACL_RULES.includes(forbidden));
  assert.throws(()=>regionalGatewayAclArguments('default','f'.repeat(64)));
});
