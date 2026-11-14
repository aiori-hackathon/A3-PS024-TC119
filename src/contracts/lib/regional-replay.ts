import { createHash } from 'node:crypto';
import { ContractError, configurationDigest, PROTOCOL, validateManifest, type Manifest } from './index.ts';
import { REGIONAL, regionalPolicyDigest, validateRegionalPolicy, type RegionalPolicy } from './regional.ts';
import { REPLAY_SCRIPTS, verifyStoreReady, type RedisIo } from './replay.ts';

export const REGIONAL_REPLAY_REVISION = 'regional-replay-1';
export const REGIONAL_POLICY_KEY = 'tfr:policy';
export const REGIONAL_SPENT_PREFIX = 'tfr:spent:';
export const REGIONAL_IP_PREFIX = 'tfr:ip-budget:';
const script=(source:string)=>Object.freeze({source,sha1:createHash('sha1').update(source).digest('hex')});

// Execute the UNCHANGED baseline read-only guards on their original two-key/three-argument ABI.
// This deliberately preserves the reviewed baseline script bytes and source hashes.
const baselineGuard=`local function baseline_snapshot()\nlocal KEYS = {KEYS[1], KEYS[2]}\nlocal ARGV = {ARGV[1], ARGV[2], ARGV[3]}\n${REPLAY_SCRIPTS.snapshot.source}\nend\n`;
const guards=String.raw`
local MAX = 9007199254740991
local function uint(s)
  if type(s) ~= 'string' or #s > 16 or (s ~= '0' and not string.match(s, '^[1-9][0-9]*$')) then return nil end
  local n = tonumber(s)
  if not n or n > MAX then return nil end
  return n
end
local function hex(s,n) return type(s) == 'string' and #s == n and string.match(s,'^[0-9a-f]+$') end
if #KEYS ~= KEY_COUNT or #ARGV ~= ARG_COUNT or KEYS[1] ~= 'pp:policy' or KEYS[2] ~= 'pp:clock'
  or KEYS[3] ~= 'tfr:policy' or not hex(ARGV[4],64)
  or (ARGV[5] ~= 'ip' and ARGV[5] ~= 'type2-bearer' and ARGV[5] ~= 'arc' and ARGV[5] ~= 'type2-holder') then return {'RUN_UNAVAILABLE'} end
local start_ms, end_ms, baseline_start = uint(ARGV[6]), uint(ARGV[7]), uint(ARGV[8])
if not start_ms or not end_ms or not baseline_start or start_ms < baseline_start
  or end_ms - start_ms ~= WINDOW_MS or end_ms > MAX - GUARD_MS
  or baseline_start > MAX - BASELINE_EPOCH_MS or end_ms > baseline_start + BASELINE_EPOCH_MS then return {'RUN_UNAVAILABLE'} end
local snap = baseline_snapshot()
if snap[1] ~= 'SNAPSHOT' then return snap end
if redis.call('HGET',KEYS[1],'run_start_ms') ~= ARGV[8] then return {'RUN_UNAVAILABLE'} end
local now = snap[5]
`;
const fields=['revision','run_id','config_digest','policy_digest','profile','window_start_ms','window_end_ms'] as const;
const policyGuard=String.raw`
if redis.call('TYPE',KEYS[3]).ok ~= 'hash' or redis.call('PTTL',KEYS[3]) ~= -1
  or redis.call('HLEN',KEYS[3]) ~= 7 then return {'RUN_UNAVAILABLE'} end
local r = redis.call('HMGET',KEYS[3],'revision','run_id','config_digest','policy_digest','profile','window_start_ms','window_end_ms')
if r[1] ~= 'regional-replay-1' or r[2] ~= ARGV[1] or r[3] ~= ARGV[3] or r[4] ~= ARGV[4]
  or r[5] ~= ARGV[5] or r[6] ~= ARGV[6] or r[7] ~= ARGV[7] then return {'RUN_UNAVAILABLE'} end
`;
const windowGuard=String.raw`
if now < start_ms then return {'WINDOW_CLOSED'} end
if now >= end_ms then
  -- Persist observed expiry across ALL workers. A later clock rollback cannot reopen this generation.
  redis.call('HSET',KEYS[2],'last_now_ms',string.format('%.0f',now),'highest_epoch',string.format('%.0f',snap[6]),'closed','1')
  return {'WINDOW_CLOSED'}
end
`;
const observeClock=String.raw`
-- Record even read/refusal observations, so a later rollback cannot revive an observed expired nonce.
redis.call('HSET',KEYS[2],'last_now_ms',string.format('%.0f',now),'highest_epoch','0')
`;
const source=(kind:'snapshot'|'claim'|'initialize')=>{
  const prelude=`local KEY_COUNT, ARG_COUNT = ${kind==='claim'?'4,10':'3,8'}\nlocal WINDOW_MS, GUARD_MS, BASELINE_EPOCH_MS = ${REGIONAL.window_ms},${PROTOCOL.guard_ms},${PROTOCOL.epoch_ms}\n`;
  let body:string;
  if(kind==='initialize')body=String.raw`
-- Controller only, while all workers are fenced. Validate everything before this one HSET.
if redis.call('DBSIZE') ~= 2 or redis.call('TYPE',KEYS[3]).ok ~= 'none' then return {'NOT_FRESH'} end
local c = redis.call('HMGET',KEYS[2],'last_now_ms','highest_epoch')
if c[1] ~= ARGV[8] or c[2] ~= '0' then return {'NOT_FRESH'} end
if now < start_ms or now >= end_ms then return {'WINDOW_CLOSED'} end
redis.call('HSET',KEYS[3],'revision','regional-replay-1','run_id',ARGV[1],'config_digest',ARGV[3],
  'policy_digest',ARGV[4],'profile',ARGV[5],'window_start_ms',ARGV[6],'window_end_ms',ARGV[7])
return {'INITIALIZED'}
`;
  else if(kind==='snapshot')body=policyGuard+windowGuard+observeClock+String.raw`
return {'REGIONAL_SNAPSHOT',ARGV[1],ARGV[4],now,start_ms,end_ms}
`;
  else body=policyGuard+String.raw`
local not_after = uint(ARGV[10])
local prefix = ARGV[5] == 'ip' and 'tfr:ip-budget:' or 'tfr:spent:'
if not hex(ARGV[9],64) or KEYS[4] ~= prefix .. ARGV[4] .. ':' .. ARGV[9] or not not_after then return {'RUN_UNAVAILABLE'} end
if (ARGV[5] == 'type2-holder' and (not_after <= start_ms or not_after > end_ms))
  or (ARGV[5] ~= 'type2-holder' and not_after ~= 0) then return {'RUN_UNAVAILABLE'} end
local expiry = end_ms + GUARD_MS
local spent_type = redis.call('TYPE',KEYS[4]).ok
local count = 0
if spent_type ~= 'none' then
  if spent_type ~= 'string' or redis.call('PEXPIRETIME',KEYS[4]) ~= expiry then return {'RUN_UNAVAILABLE'} end
  local raw = redis.call('GET',KEYS[4])
  count = uint(raw)
  if not count or count < 1 or count > (ARGV[5] == 'ip' and 25 or 1) then return {'RUN_UNAVAILABLE'} end
end
`+windowGuard+observeClock+String.raw`
if ARGV[5] == 'type2-holder' and now >= not_after then return {'NONCE_EXPIRED'} end
if ARGV[5] == 'ip' then
  if count >= 25 then return {'LIMIT_REACHED'} end
  redis.call('SET',KEYS[4],string.format('%.0f',count+1),'PXAT',string.format('%.0f',expiry))
  return {'CLAIMED',expiry}
end
-- Redis serializes TIME validation and SET NX. Errors after a mutation are uncertain, never retried.
local inserted = redis.call('SET',KEYS[4],'1','NX','PXAT',string.format('%.0f',expiry))
if inserted then return {'CLAIMED',expiry} end
return {'ALREADY_SPENT'}
`;
  return prelude+baselineGuard+guards+body;
};
export const REGIONAL_REPLAY_SCRIPTS=Object.freeze({snapshot:script(source('snapshot')),claim:script(source('claim'))});
export const REGIONAL_REPLAY_INITIALIZER=script(source('initialize'));

function checked(configuration:unknown,policy:unknown):{manifest:Manifest;policy:RegionalPolicy} {
  const m=validateManifest(structuredClone(configuration));
  if(m.snapshot_script_sha1!==REPLAY_SCRIPTS.snapshot.sha1||m.claim_script_sha1!==REPLAY_SCRIPTS.claim.sha1)
    throw new ContractError('regional-replay-baseline-script');
  const p=validateRegionalPolicy(policy,m);
  return {manifest:m,policy:p};
}
export function regionalReplayIdentity(configuration:unknown,policy:unknown):readonly string[] {
  const {manifest:m,policy:p}=checked(configuration,policy);
  return Object.freeze([m.run_id,m.token_key_id,configurationDigest(m),regionalPolicyDigest(p),p.profile,
    String(p.window_start_ms),String(p.window_end_ms),String(m.run_start_ms)]);
}
export function regionalStoreState(configuration:unknown,policy:unknown):Readonly<Record<string,string>> {
  const a=regionalReplayIdentity(configuration,policy);
  return Object.freeze(Object.fromEntries(fields.map((field,i)=>[field,[REGIONAL_REPLAY_REVISION,a[0]!,a[2]!,a[3]!,a[4]!,a[5]!,a[6]!][i]!])));
}
export function regionalSnapshotCommand(configuration:unknown,policy:unknown):(string|number)[] {
  return ['EVALSHA',REGIONAL_REPLAY_SCRIPTS.snapshot.sha1,3,'pp:policy','pp:clock',REGIONAL_POLICY_KEY,
    ...regionalReplayIdentity(configuration,policy)];
}
export function regionalClaimCommand(configuration:unknown,policy:unknown,spendId:string,notAfterMs=0):(string|number)[] {
  const {policy:p}=checked(configuration,policy);
  if(typeof spendId!=='string'||!/^[0-9a-f]{64}$/.test(spendId)||!Number.isSafeInteger(notAfterMs)||Object.is(notAfterMs,-0)
    || (p.profile==='type2-holder'?(notAfterMs<=p.window_start_ms||notAfterMs>p.window_end_ms):notAfterMs!==0))
    throw new ContractError('regional-replay-candidate');
  const identity=regionalReplayIdentity(configuration,p);
  return ['EVALSHA',REGIONAL_REPLAY_SCRIPTS.claim.sha1,4,'pp:policy','pp:clock',REGIONAL_POLICY_KEY,
    `${p.profile==='ip'?REGIONAL_IP_PREFIX:REGIONAL_SPENT_PREFIX}${identity[3]}:${spendId}`,...identity,spendId,String(notAfterMs)];
}

const fail=():never=>{throw new ContractError('regional-replay-unsafe');};
export type RegionalSnapshotReply={tag:'REGIONAL_SNAPSHOT';now_ms:number}|{tag:'WINDOW_CLOSED'|'RUN_UNAVAILABLE'|'CLOCK_UNSAFE'};
export type RegionalClaimReply={tag:'CLAIMED';expiry_ms:number}|{tag:'LIMIT_REACHED'|'ALREADY_SPENT'|'WINDOW_CLOSED'|'NONCE_EXPIRED'|'RUN_UNAVAILABLE'|'CLOCK_UNSAFE'};
const errors=['WINDOW_CLOSED','RUN_UNAVAILABLE','CLOCK_UNSAFE'];
export function parseRegionalSnapshot(reply:unknown,configuration:unknown,policy:unknown):RegionalSnapshotReply {
  const {manifest:m,policy:p}=checked(configuration,policy);
  if(!Array.isArray(reply)||typeof reply[0]!=='string')return fail();
  if(reply.length===1&&errors.includes(reply[0]))return {tag:reply[0] as 'WINDOW_CLOSED'|'RUN_UNAVAILABLE'|'CLOCK_UNSAFE'};
  if(reply.length!==6||reply[0]!=='REGIONAL_SNAPSHOT'||reply[1]!==m.run_id||reply[2]!==regionalPolicyDigest(p)
    ||!Number.isSafeInteger(reply[3])||reply[3]<p.window_start_ms||reply[3]>=p.window_end_ms
    ||reply[4]!==p.window_start_ms||reply[5]!==p.window_end_ms)return fail();
  return {tag:'REGIONAL_SNAPSHOT',now_ms:reply[3]};
}
export function parseRegionalClaim(reply:unknown,configuration:unknown,policy:unknown):RegionalClaimReply {
  const {policy:p}=checked(configuration,policy);
  if(!Array.isArray(reply)||typeof reply[0]!=='string')return fail();
  if(reply.length===1&&[...errors,'LIMIT_REACHED','ALREADY_SPENT','NONCE_EXPIRED'].includes(reply[0])){
    if((reply[0]==='LIMIT_REACHED'&&p.profile!=='ip')||(reply[0]==='ALREADY_SPENT'&&p.profile==='ip'))return fail();
    if(reply[0]==='NONCE_EXPIRED'&&p.profile!=='type2-holder')return fail();
    return {tag:reply[0] as Exclude<RegionalClaimReply['tag'],'CLAIMED'>};
  }
  if(reply.length!==2||reply[0]!=='CLAIMED'||reply[1]!==p.window_end_ms+PROTOCOL.guard_ms)return fail();
  return {tag:'CLAIMED',expiry_ms:reply[1]};
}

/** Controller-only sequence: baseline fresh readiness FIRST, then append regional state. No retries. */
export async function initializeRegionalStore(io:RedisIo,configuration:unknown,policy:unknown):Promise<void> {
  const identity=regionalReplayIdentity(configuration,policy);
  try {
    await verifyStoreReady(io,configuration);
    for(const s of [...Object.values(REGIONAL_REPLAY_SCRIPTS),REGIONAL_REPLAY_INITIALIZER])
      if(await io.call('SCRIPT','LOAD',s.source)!==s.sha1)return fail();
    const reply=await io.call('EVALSHA',REGIONAL_REPLAY_INITIALIZER.sha1,3,'pp:policy','pp:clock',REGIONAL_POLICY_KEY,...identity);
    if(!Array.isArray(reply)||reply.length!==1||reply[0]!=='INITIALIZED')return fail();
    await verifyRegionalStoreReady(io,configuration,policy,true);
  } catch {throw new ContractError('regional-replay-bootstrap-failed');}
}
/** Controller/worker readiness. Only controller initialization requires three keys; no live repair. */
export async function verifyRegionalStoreReady(io:RedisIo,configuration:unknown,policy:unknown,fresh=false):Promise<void> {
  const expected=regionalStoreState(configuration,policy);
  const exists=await io.call('SCRIPT','EXISTS',...Object.values(REGIONAL_REPLAY_SCRIPTS).map(s=>s.sha1));
  if(!Array.isArray(exists)||exists.length!==2||exists.some(v=>v!==1))return fail();
  if(await io.call('TYPE',REGIONAL_POLICY_KEY)!=='hash'||await io.call('PTTL',REGIONAL_POLICY_KEY)!==-1
    ||await io.call('HLEN',REGIONAL_POLICY_KEY)!==fields.length)return fail();
  const values=await io.call('HMGET',REGIONAL_POLICY_KEY,...fields);
  if(!Array.isArray(values)||values.length!==fields.length||values.some((v,i)=>v!==expected[fields[i]!]))return fail();
  if(fresh&&await io.call('DBSIZE')!==3)return fail();
  const cmd=regionalSnapshotCommand(configuration,policy);
  const snapshot=parseRegionalSnapshot(await io.call(cmd[0] as string,...cmd.slice(1)),configuration,policy);
  if(snapshot.tag!=='REGIONAL_SNAPSHOT')return fail();
}

/** Separate account; no pp:spent access, policy writes, initializer loading or state administration. */
export const REGIONAL_GATEWAY_ACL_RULES=Object.freeze([
  '%R~pp:policy','%RW~pp:clock','%R~tfr:policy','%RW~tfr:spent:*','%RW~tfr:ip-budget:*','-@all',
  '+auth','+type','+pttl','+hlen','+hmget','+hget','+time','+get','+pexpiretime','+hset','+set','+script|exists',
  // EVALSHA declares all KEYS read/write. A command-only selector permits invocation,
  // while inner HSET/SET still use the restrictive root command/key permissions.
  '(+evalsha %RW~pp:policy %RW~pp:clock %RW~tfr:policy %RW~tfr:spent:* %RW~tfr:ip-budget:*)'
]);
export function regionalGatewayAclArguments(username:string,password:string):string[] {
  if(typeof username!=='string'||!/^tfr_[a-zA-Z0-9_-]{1,59}$/.test(username)
    ||typeof password!=='string'||!/^[0-9a-f]{64}$/.test(password))throw new ContractError('regional-replay-acl');
  return ['SETUSER',username,'reset','on',`>${password}`,...REGIONAL_GATEWAY_ACL_RULES];
}
