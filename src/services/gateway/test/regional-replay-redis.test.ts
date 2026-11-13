import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import golden from '../../../contracts/fixtures/policy-golden.json' with {type:'json'};
import { configurationDigest, makeManifest, type Manifest } from '../../../contracts/lib/index.ts';
import { initialStoreState, initializeStore, loadReplayScripts, parseRedisTime, REPLAY_SCRIPTS, type RedisIo } from '../../../contracts/lib/replay.ts';
import { REGIONAL, regionalPolicyDigest, validateRegionalPolicy, type RegionalPolicy } from '../../../contracts/lib/regional.ts';
import { initializeRegionalStore, regionalClaimCommand, regionalSnapshotCommand, regionalStoreState,
  parseRegionalClaim, REGIONAL_REPLAY_SCRIPTS, regionalGatewayAclArguments } from '../../../contracts/lib/regional-replay.ts';

// One isolated TEST Redis, no published ports, persistence, external network or host mounts.
const image='redis@sha256:efc27681bf81e6ed55cb581718b7818c6c04c39b1f9aa40854edd3ea2241b6ed';
const exec=promisify(execFile);let container='';let m:Manifest,p:RegionalPolicy;
async function docker(...args:string[]):Promise<string>{
  const result=await exec('docker',args,{encoding:'utf8',timeout:30000,maxBuffer:1024*1024});return result.stdout.trim();
}
async function command(...args:(string|number)[]):Promise<any>{
  const raw=await docker('exec',container,'redis-cli','--json',...args.map(String));
  if(raw.startsWith('error:'))throw Error('Isolated regional Redis command refused');return JSON.parse(raw);
}
const io:RedisIo={call:(cmd,...args)=>command(cmd,...args)};
before(async()=>{
  container=await docker('run','-d','--rm','--network','none','--user','redis','--read-only',
    '--tmpfs','/data:rw,noexec,nosuid,size=8m','--cap-drop','ALL','--security-opt','no-new-privileges',
    '--memory','384m','--pids-limit','128','--log-driver','none','--label',`tokenforge.test=regional-replay-${process.pid}`,image,'redis-server','--bind','127.0.0.1',
    '--save','','--appendonly','no','--maxmemory','268435456','--maxmemory-policy','noeviction',
    '--slowlog-log-slower-than','-1','--slowlog-max-len','0','--acllog-max-len','0');
  for(let n=0;n<30;n++){try{if(await command('PING')==='PONG')return;}catch{/* bounded startup */}await delay(100);}
  throw Error('Isolated regional Redis startup failed');
});
after(async()=>{if(container)await docker('rm','-f',container);});
async function seed(profile:'arc'|'type2-holder'='arc',closed=false){
  await command('FLUSHDB');await loadReplayScripts(io);
  const now=parseRedisTime(await command('TIME'));
  m=makeManifest({run_id:golden.manifest.run_id,run_start_ms:now-(closed?61000:5000),
    token_key_spki_b64url:golden.manifest.token_key_spki_b64url,
    snapshot_script_sha1:REPLAY_SCRIPTS.snapshot.sha1,claim_script_sha1:REPLAY_SCRIPTS.claim.sha1});
  p=validateRegionalPolicy({contract_version:REGIONAL.contract_version,schema_version:1,run_id:m.run_id,
    baseline_config_digest:configurationDigest(m),profile,window_start_ms:m.run_start_ms,window_end_ms:m.run_start_ms+60000,
    quota:5,admitted_entitlements:5,resource_id:REGIONAL.resource_id,method:REGIONAL.method,url:REGIONAL.url,
    type2_key_id:profile==='type2-holder'?m.token_key_id:null,arc_key_id:profile==='arc'?'a'.repeat(64):null,
    arc_implementation_revision:profile==='arc'?'b'.repeat(40):null,arc_tag_encoding:profile==='arc'?REGIONAL.arc_tag_encoding:null},m);
  await initializeStore(io,m);
  if(closed){
    // TEST fixture of a previously initialized now-expired window; never a production clock seam.
    for(const s of Object.values(REGIONAL_REPLAY_SCRIPTS))await command('SCRIPT','LOAD',s.source);
    await command('HSET','tfr:policy',...Object.entries(regionalStoreState(m,p)).flat());
  }else await initializeRegionalStore(io,m,p);
}
const spend='c'.repeat(64);
const key=()=>`tfr:spent:${regionalPolicyDigest(p)}:${spend}`;
async function claim(id=spend,notAfter=0){const cmd=regionalClaimCommand(m,p,id,notAfter);return command(...cmd);}
async function restoreFixture(){
  const state=initialStoreState(m);
  // Admin-only fixture reset in THIS disposable server. Production initializer is exercised separately above.
  await command('EVAL',`redis.call('DEL',unpack(KEYS))
    for key,fields in pairs(cjson.decode(ARGV[1])) do
      local args = {}; for field,value in pairs(fields) do table.insert(args,field);table.insert(args,value) end
      redis.call('HSET',key,unpack(args))
    end
    return 'OK'`,4,'pp:policy','pp:clock','tfr:policy',key(),
    JSON.stringify({'pp:policy':state.policy,'pp:clock':state.clock,'tfr:policy':regionalStoreState(m,p)}));
}
async function testClockClaim(now:number,notAfter=0){
  // Test-only source copy with exactly one TIME substitution; no production option, host clock change or runtime hook.
  const source=REGIONAL_REPLAY_SCRIPTS.claim.source;
  assert.equal(source.split("local time = redis.call('TIME')").length,2);
  const timed=source.replace("local time = redis.call('TIME')",
    `local time = {'${Math.floor(now/1000)}','${(now%1000)*1000}'}`);
  const cmd=regionalClaimCommand(m,p,spend,notAfter);
  return command('EVAL',timed,...cmd.slice(2));
}

test('real Redis bootstrap is additive, single-use and refuses live policy replacement',async()=>{
  await seed();assert.equal(await command('DBSIZE'),3);
  const cmd=regionalSnapshotCommand(m,p),reply=await command(...cmd);
  assert.equal(reply[0],'REGIONAL_SNAPSHOT');assert.equal(await command('PTTL','tfr:policy'),-1);
  const before=await command('HGETALL','tfr:policy');
  await assert.rejects(()=>initializeRegionalStore(io,m,p),/regional-replay-bootstrap-failed/);
  assert.deepEqual(await command('HGETALL','tfr:policy'),before);
  assert.equal(await command('DBSIZE'),3);
});

test('twenty independent invocations claim one regional spend once with exact retention',async()=>{
  await seed();const replies=await Promise.all(Array.from({length:20},()=>claim()));
  replies.forEach(r=>parseRegionalClaim(r,m,p));
  assert.equal(replies.filter(r=>r[0]==='CLAIMED').length,1);
  assert.equal(replies.filter(r=>r[0]==='ALREADY_SPENT').length,19);
  assert.equal(await command('GET',key()),'1');
  assert.equal(await command('PEXPIRETIME',key()),p.window_end_ms+30000);
  assert.equal(await command('EXISTS',`pp:spent:${spend}`),0);
});

test('regional expiry refuses while the unchanged baseline epoch is still valid',async()=>{
  await seed('arc',true);
  const baseline=await command('EVALSHA',REPLAY_SCRIPTS.snapshot.sha1,2,'pp:policy','pp:clock',m.run_id,m.token_key_id,configurationDigest(m));
  assert.equal(baseline[0],'SNAPSHOT');assert.equal(baseline[5],0);
  assert.deepEqual(await claim(),['WINDOW_CLOSED']);assert.equal(await command('EXISTS',key()),0);
});

test('expired holder nonce does not spend; a fresh validated expiry permits the same owner candidate',async()=>{
  await seed('type2-holder');const now=parseRedisTime(await command('TIME'));
  assert.deepEqual(await claim(spend,now-1000),['NONCE_EXPIRED']);assert.equal(await command('EXISTS',key()),0);
  assert.deepEqual(await claim(spend,p.window_end_ms),['CLAIMED',p.window_end_ms+30000]);
  assert.deepEqual(await claim(spend,p.window_end_ms),['ALREADY_SPENT']);
});

test('corrupt policy/clock/spent guards refuse without repair or a new spend',async()=>{
  await seed();
  const mutations:[string[],string][]=[
    [['DEL','tfr:policy'],'RUN_UNAVAILABLE'],[['HSET','tfr:policy','extra','1'],'RUN_UNAVAILABLE'],
    [['HSET','tfr:policy','window_end_ms','1'],'RUN_UNAVAILABLE'],[['PEXPIRE','tfr:policy','60000'],'RUN_UNAVAILABLE'],
    [['HSET','pp:clock','closed','1'],'RUN_UNAVAILABLE'],[['DEL','pp:clock'],'RUN_UNAVAILABLE']
  ];
  for(const [mutation,expected] of mutations){
    await restoreFixture();await command(...mutation);assert.deepEqual(await claim(),[expected]);assert.equal(await command('EXISTS',key()),0);
  }
  await restoreFixture();await command('HSET','pp:clock','last_now_ms',String(m.run_start_ms+55000),'highest_epoch','0');
  assert.deepEqual(await claim(),['CLOCK_UNSAFE']);assert.equal(await command('EXISTS',key()),0);
  for(const value of ['wrong','1']){
    await restoreFixture();await command('SET',key(),value); // Missing exact PXAT is unsafe even when value is 1.
    assert.deepEqual(await claim(),['RUN_UNAVAILABLE']);assert.equal(await command('GET',key()),value);
  }
});

test('observed window closure and expired-nonce highwater cannot be revived by rollback',async()=>{
  await seed('type2-holder');
  assert.deepEqual(await testClockClaim(p.window_end_ms,p.window_end_ms),['WINDOW_CLOSED']);
  assert.equal(await command('HGET','pp:clock','closed'),'1');
  assert.deepEqual(await claim(spend,p.window_end_ms),['RUN_UNAVAILABLE']);
  await restoreFixture();const now=parseRedisTime(await command('TIME'));
  assert.deepEqual(await testClockClaim(now+5000,now+4000),['NONCE_EXPIRED']);
  assert.equal(await command('EXISTS',key()),0);
  assert.deepEqual(await claim(spend,p.window_end_ms),['CLOCK_UNSAFE']);
});

test('regional ACL permits claims but denies policy writes, baseline spends and administration',async()=>{
  await seed();
  // Public TEST-only credential on a disposable network-none server. Never a deployment password.
  await command('ACL',...regionalGatewayAclArguments('tfr_test','ab'.repeat(32)));
  for(const args of [['HMGET','tfr:policy','revision'],['HSET','pp:clock','last_now_ms','1'],['GET',key()],
    ['SET',key(),'1'],['SCRIPT','EXISTS',REGIONAL_REPLAY_SCRIPTS.claim.sha1]])
    assert.equal(await command('ACL','DRYRUN','tfr_test',...args),'OK');
  for(const args of [['SET','tfr:policy','wrong'],['HSET','pp:policy','run_id','wrong'],['GET','pp:spent:'+spend],
    ['SCRIPT','LOAD','return 1'],['FLUSHDB'],['CONFIG','GET','*'],['DEL',key()]])
    assert.notEqual(await command('ACL','DRYRUN','tfr_test',...args),'OK');
});
