import { createHash } from 'node:crypto';
import { PROTOCOL } from './index.ts';

// Both scripts use exactly the same bounded, read-only guard validation.
// No caller-supplied timestamp or test clock is present in production Lua.
const guards = String.raw`
local MAX = 9007199254740991
local function uint(s)
  if type(s) ~= 'string' or #s > 16 then return nil end
  if s ~= '0' and not string.match(s, '^[1-9][0-9]*$') then return nil end
  local n = tonumber(s)
  if not n or n > MAX then return nil end
  return n
end
local function hex(s, len)
  return type(s) == 'string' and #s == len and string.match(s, '^[0-9a-f]+$')
end
local function kind(key) return redis.call('TYPE', key).ok end
local function hash(key, fields)
  if kind(key) ~= 'hash' or redis.call('PTTL', key) ~= -1 or redis.call('HLEN', key) ~= #fields then return nil end
  local values = redis.call('HMGET', key, unpack(fields))
  for i = 1, #fields do if type(values[i]) ~= 'string' then return nil end end
  return values
end
if #KEYS ~= KEY_COUNT or #ARGV ~= ARG_COUNT or KEYS[1] ~= 'pp:policy' or KEYS[2] ~= 'pp:clock'
  or not hex(ARGV[1], 32) or not hex(ARGV[2], 64) or not hex(ARGV[3], 64) then return {'RUN_UNAVAILABLE'} end
local p = hash(KEYS[1], {'schema_version', 'run_id', 'token_type', 'token_key_id', 'config_digest', 'run_start_ms', 'epoch_ms', 'guard_ms'})
local c = hash(KEYS[2], {'run_id', 'last_now_ms', 'highest_epoch', 'closed'})
if not p or not c or p[1] ~= '1' or p[2] ~= ARGV[1] or p[3] ~= TOKEN_TYPE
  or p[4] ~= ARGV[2] or p[5] ~= ARGV[3] or p[7] ~= EPOCH_MS or p[8] ~= GUARD_MS
  or c[1] ~= ARGV[1] or c[4] ~= '0' then return {'RUN_UNAVAILABLE'} end
local run_start = uint(p[6])
local last = uint(c[2])
local highest = uint(c[3])
if not run_start or not last or not highest then return {'RUN_UNAVAILABLE'} end
local epoch_ms, guard_ms = tonumber(EPOCH_MS), tonumber(GUARD_MS)
if last < run_start or math.floor((last - run_start) / epoch_ms) ~= highest then return {'CLOCK_UNSAFE'} end
local time = redis.call('TIME')
local seconds, micros = uint(time[1]), uint(time[2])
-- TIME microseconds can have leading zeroes on some implementations. Redis 7
-- returns canonical decimal; any unexpected representation is unsafe here.
if not seconds or not micros or micros >= 1000000 or seconds > math.floor(MAX / 1000) then return {'CLOCK_UNSAFE'} end
local now = seconds * 1000 + math.floor(micros / 1000)
if now > MAX or now < run_start or now < last then return {'CLOCK_UNSAFE'} end
local epoch = math.floor((now - run_start) / epoch_ms)
local start_ms = run_start + epoch * epoch_ms
-- Bound additions before performing them; no rounded unsafe expiry is allowed.
if start_ms > MAX - epoch_ms - guard_ms then return {'CLOCK_UNSAFE'} end
local end_ms = start_ms + epoch_ms
local expiry = end_ms + guard_ms
local function decimal(n) return string.format('%.0f', n) end
`;

function source(claim: boolean): string {
  const prelude = `local KEY_COUNT, ARG_COUNT = ${claim ? '3, 5' : '2, 3'}\n` +
    `local TOKEN_TYPE, EPOCH_MS, GUARD_MS = '${PROTOCOL.token_type}', '${PROTOCOL.epoch_ms}', '${PROTOCOL.guard_ms}'\n`;
  return prelude + guards + (claim ? String.raw`
local candidate = uint(ARGV[4])
if not candidate or not hex(ARGV[5], 64) or KEYS[3] ~= 'pp:spent:' .. ARGV[5] then return {'RUN_UNAVAILABLE'} end
if candidate ~= epoch then return {'EPOCH_CLOSED'} end
local spent_type = kind(KEYS[3])
if spent_type ~= 'none' then
  if spent_type ~= 'string' or redis.call('GET', KEYS[3]) ~= '1'
    or redis.call('PEXPIRETIME', KEYS[3]) ~= expiry then return {'RUN_UNAVAILABLE'} end
end
-- Validation is complete. Redis serializes the entire script, including NX.
-- Runtime/ACL/OOM errors are NOT rolled back: the adapter must latch closure
-- on any script/transport error or ambiguous outcome, without retrying.
redis.call('HSET', KEYS[2], 'last_now_ms', decimal(now), 'highest_epoch', decimal(epoch))
local inserted = redis.call('SET', KEYS[3], '1', 'NX', 'PXAT', decimal(expiry))
if inserted then return {'CLAIMED', expiry} end
return {'ALREADY_SPENT'}
` : String.raw`
return {'SNAPSHOT', p[2], p[4], p[5], now, epoch, start_ms, end_ms}
`);
}

function script(lua: string) {
  return Object.freeze({ source: lua, sha1: createHash('sha1').update(lua, 'utf8').digest('hex') });
}

/** Controller loads these exact bytes BEFORE enabling a fresh run; workers only EVALSHA.
 * Any unsafe result requires terminal local run closure (snapshot is read-only).
 * Script SHA-1 identifies source, not token security. Never reload on a live run.
 */
export const REPLAY_SCRIPTS = Object.freeze({ snapshot: script(source(false)), claim: script(source(true)) });

// ---------------------------------------------------------------------------------------------------------------
// Controller-side bootstrap API (additive revision `replay-bootstrap-1`; the TF-PS024-1.0.0 wire contract is unchanged).
//
// The controller is the only party that loads scripts, writes policy/clock and administers ACLs. This module gives it
// exactly what the gateway's own Redis tests use, so the lab never copies or re-derives any of it:
//   readRunStart      run_start_ms comes from the exact Redis instance's TIME, never the host clock
//   loadReplayScripts the exact snapshot/claim bytes (and the controller-only initializer) are loaded and hash-checked
//   initializeStore   ONE atomic script writes the eight-field policy and four-field clock, and only into an EMPTY store
//   installGatewayAcl the minimal gateway account (no script loading, no administration, no other keys)
//   verifyStoreReady  field-by-field readiness comparison before ENABLE
// Nothing here retries. An uncertain outcome (transport loss, unexpected reply) throws `replay-bootstrap-uncertain`
// and the run must be closed and reset: Redis script errors are not rolled back, so a partial write is possible.
// No password, token or voucher is stored in this module or included in any error.
import { ContractError } from './schema.ts';
import { configurationDigest, parseSnapshotReply, validateManifest, type Manifest } from './index.ts';

export const REPLAY_BOOTSTRAP_REVISION = 'replay-bootstrap-1';

/** The only Redis capability the bootstrap needs: issue one command, get the decoded reply. ioredis `call` fits. */
export interface RedisIo { call(command: string, ...args: (string | number)[]): Promise<unknown>; }

export const POLICY_KEY = 'pp:policy';
export const CLOCK_KEY = 'pp:clock';
export const SPENT_PREFIX = 'pp:spent:';
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

/** Controller-only. Never granted to the gateway account and never loaded by a worker. */
const initializerSource = `local KEY_COUNT, ARG_COUNT = 2, 4
local TOKEN_TYPE, EPOCH_MS, GUARD_MS = '${PROTOCOL.token_type}', '${PROTOCOL.epoch_ms}', '${PROTOCOL.guard_ms}'
` + String.raw`
local MAX = 9007199254740991
local function uint(s)
  if type(s) ~= 'string' or #s > 16 then return nil end
  if s ~= '0' and not string.match(s, '^[1-9][0-9]*$') then return nil end
  local n = tonumber(s)
  if not n or n > MAX then return nil end
  return n
end
local function hex(s, len) return type(s) == 'string' and #s == len and string.match(s, '^[0-9a-f]+$') end
-- Every check happens before the first write. Redis does not roll back after a runtime error.
if #KEYS ~= KEY_COUNT or #ARGV ~= ARG_COUNT or KEYS[1] ~= 'pp:policy' or KEYS[2] ~= 'pp:clock'
  or not hex(ARGV[1], 32) or not hex(ARGV[2], 64) or not hex(ARGV[3], 64) then return {'INVALID'} end
local start = uint(ARGV[4])
if not start or start < 1 then return {'INVALID'} end
if redis.call('DBSIZE') ~= 0 then return {'NOT_EMPTY'} end
local time = redis.call('TIME')
local seconds, micros = uint(time[1]), uint(time[2])
if not seconds or not micros or micros >= 1000000 or seconds > math.floor(MAX / 1000) then return {'CLOCK_UNSAFE'} end
local now = seconds * 1000 + math.floor(micros / 1000)
if now < start then return {'CLOCK_UNSAFE'} end
redis.call('HSET', KEYS[1], 'schema_version', '1', 'run_id', ARGV[1], 'token_type', TOKEN_TYPE, 'token_key_id', ARGV[2],
  'config_digest', ARGV[3], 'run_start_ms', ARGV[4], 'epoch_ms', EPOCH_MS, 'guard_ms', GUARD_MS)
redis.call('HSET', KEYS[2], 'run_id', ARGV[1], 'last_now_ms', ARGV[4], 'highest_epoch', '0', 'closed', '0')
return {'INITIALIZED'}
`;
export const REPLAY_INITIALIZER = script(initializerSource);

const fail = (reason: string): never => { throw new ContractError(`replay-bootstrap-${reason}`); };

/** Canonical decimal only; leading zeros, signs, exponents and non-strings are unsafe. */
function decimal(value: unknown, max = MAX_SAFE): number {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max) return value;
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,15})$/.test(value)) return fail('time-invalid');
  const n = Number(value);
  return Number.isSafeInteger(n) && n <= max ? n : fail('time-invalid');
}

/** Redis TIME reply `[seconds, microseconds]` -> milliseconds since the epoch. */
export function parseRedisTime(reply: unknown): number {
  if (!Array.isArray(reply) || reply.length !== 2) return fail('time-invalid');
  const seconds = decimal(reply[0], Math.floor(MAX_SAFE / 1000)), micros = decimal(reply[1], 999_999);
  return seconds * 1000 + Math.floor(micros / 1000);
}

const transport = async <T>(work: () => Promise<T>): Promise<T> => {
  try { return await work(); } catch (e) { if (e instanceof ContractError) throw e; return fail('uncertain'); }
};

/** `run_start_ms` for a fresh run: this Redis instance's own clock. */
export async function readRunStart(io: RedisIo): Promise<number> {
  const start = parseRedisTime(await transport(() => io.call('TIME')));
  return start >= 1 ? start : fail('time-invalid');
}

/** Loads the exact bytes of the two replay scripts and the initializer; each returned hash must match. */
export async function loadReplayScripts(io: RedisIo): Promise<void> {
  for (const s of [REPLAY_SCRIPTS.snapshot, REPLAY_SCRIPTS.claim, REPLAY_INITIALIZER]) {
    const sha = await transport(() => io.call('SCRIPT', 'LOAD', s.source));
    if (sha !== s.sha1) fail('script-mismatch');
  }
}

function checkedManifest(configuration: unknown): Manifest {
  let m: Manifest;
  try { m = validateManifest(structuredClone(configuration)); } catch { return fail('manifest-invalid'); }
  if (m.snapshot_script_sha1 !== REPLAY_SCRIPTS.snapshot.sha1 || m.claim_script_sha1 !== REPLAY_SCRIPTS.claim.sha1) return fail('script-mismatch');
  return m;
}

/** The identity arguments the snapshot and claim scripts take. */
export const policyIdentity = (m: Manifest): readonly [string, string, string] => [m.run_id, m.token_key_id, configurationDigest(m)];

/** The exact initial hashes a fresh run must have. */
export function initialStoreState(m: Manifest) {
  const [run_id, token_key_id, config_digest] = policyIdentity(m);
  return {
    policy: { schema_version: '1', run_id, token_type: String(PROTOCOL.token_type), token_key_id, config_digest, run_start_ms: String(m.run_start_ms),
      epoch_ms: String(PROTOCOL.epoch_ms), guard_ms: String(PROTOCOL.guard_ms) } as Record<string, string>,
    clock: { run_id, last_now_ms: String(m.run_start_ms), highest_epoch: '0', closed: '0' } as Record<string, string>,
  };
}

/**
 * Writes the immutable policy and initial clock in one atomic script, and only into an empty store. A populated store,
 * a bad argument or an unsafe clock is refused before any write. Do not call twice and do not retry on `uncertain`.
 */
export async function initializeStore(io: RedisIo, configuration: unknown): Promise<void> {
  const m = checkedManifest(configuration);
  const reply = await transport(() => io.call('EVALSHA', REPLAY_INITIALIZER.sha1, 2, POLICY_KEY, CLOCK_KEY, ...policyIdentity(m), String(m.run_start_ms)));
  if (!Array.isArray(reply) || reply.length !== 1) return fail('uncertain');
  switch (reply[0]) {
    case 'INITIALIZED': return;
    case 'NOT_EMPTY': return fail('store-not-empty');
    case 'CLOCK_UNSAFE': return fail('clock-unsafe');
    case 'INVALID': return fail('invalid-arguments');
    default: return fail('uncertain');
  }
}

/** The gateway account: exactly what the scripts and the pinned client need. No SCRIPT LOAD, no CONFIG, no ACL, no FLUSH. */
export const GATEWAY_ACL_RULES = Object.freeze([
  '~pp:policy', '~pp:clock', '~pp:spent:*', '-@all',
  '+auth', '+type', '+pttl', '+hlen', '+hmget', '+time', '+get', '+pexpiretime', '+hset', '+set', '+evalsha', '+script|exists',
] as const);
const ACL_USER = /^[a-zA-Z0-9_-]{1,64}$/;
/** Printable, no spaces, long enough to be a generated secret; the caller generates it and keeps it private. */
const ACL_PASSWORD = /^[\x21-\x7e]{32,256}$/;

/** `ACL SETUSER` arguments. The password is supplied by the caller and never stored or echoed here. */
export function gatewayAclArgs(username: string, password: string): string[] {
  if (!ACL_USER.test(username) || username === 'default' || !ACL_PASSWORD.test(password)) return fail('acl-invalid');
  return ['SETUSER', username, 'reset', 'on', `>${password}`, ...GATEWAY_ACL_RULES];
}
export async function installGatewayAcl(io: RedisIo, username: string, password: string): Promise<void> {
  const args = gatewayAclArgs(username, password);
  if ((await transport(() => io.call('ACL', ...args))) !== 'OK') fail('acl-invalid');
}

const SNAP = (m: Manifest) => ['EVALSHA', REPLAY_SCRIPTS.snapshot.sha1, 2, POLICY_KEY, CLOCK_KEY, ...policyIdentity(m)] as (string | number)[];
// What the gateway account must be able to do, and must not, checked with ACL DRYRUN (no side effects).
const ACL_ALLOW: (string | number)[][] = [
  ['EVALSHA', REPLAY_SCRIPTS.snapshot.sha1, 2, POLICY_KEY, CLOCK_KEY], ['TIME'], ['SCRIPT', 'EXISTS', REPLAY_SCRIPTS.claim.sha1],
  ['SET', `${SPENT_PREFIX}${'a'.repeat(64)}`, '1'], ['HMGET', POLICY_KEY, 'run_id'],
];
const ACL_DENY: (string | number)[][] = [
  ['SCRIPT', 'LOAD', 'return 1'], ['SCRIPT', 'FLUSH'], ['EVAL', 'return 1', 0], ['FLUSHDB'], ['FLUSHALL'], ['CONFIG', 'GET', '*'], ['ACL', 'LIST'], ['KEYS', '*'],
  ['DEL', POLICY_KEY], ['DEL', CLOCK_KEY], ['GET', 'other'], ['SET', 'other', '1'], ['CLIENT', 'KILL', 'ID', 1], ['SHUTDOWN'], ['DEBUG', 'SLEEP', 0],
];

function pairs(reply: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (Array.isArray(reply) && reply.length % 2 === 0) {
    for (let i = 0; i < reply.length; i += 2) { if (typeof reply[i] !== 'string' || typeof reply[i + 1] !== 'string' || reply[i]! in out) return fail('not-ready-hash'); out[reply[i] as string] = reply[i + 1] as string; }
    return out;
  }
  if (reply && typeof reply === 'object' && !Array.isArray(reply)) {
    for (const [k, v] of Object.entries(reply)) { if (typeof v !== 'string') return fail('not-ready-hash'); out[k] = v; }
    return out;
  }
  return fail('not-ready-hash');
}

/**
 * Before ENABLE: the store is EXACTLY a fresh run for this manifest. Compares every immutable policy field (not only a
 * stored digest), hash types, field counts, absence of TTLs, the exact initial clock, an otherwise empty keyspace, script
 * availability, the authoritative snapshot, and (when a username is given) the gateway account's permissions.
 */
export async function verifyStoreReady(io: RedisIo, configuration: unknown, gatewayUsername?: string): Promise<void> {
  const m = checkedManifest(configuration);
  const want = initialStoreState(m);
  const call = (...a: (string | number)[]) => transport(() => io.call(...(a as [string, ...(string | number)[]])));
  const exists = await call('SCRIPT', 'EXISTS', REPLAY_SCRIPTS.snapshot.sha1, REPLAY_SCRIPTS.claim.sha1);
  if (!Array.isArray(exists) || exists.length !== 2 || exists.some((v) => Number(v) !== 1)) fail('scripts-missing');
  for (const [key, expected, code] of [[POLICY_KEY, want.policy, 'policy-invalid'], [CLOCK_KEY, want.clock, 'clock-invalid']] as const) {
    if ((await call('TYPE', key)) !== 'hash' || Number(await call('PTTL', key)) !== -1 || Number(await call('HLEN', key)) !== Object.keys(expected).length) fail(code);
    const actual = pairs(await call('HGETALL', key));
    const keys = Object.keys(expected);
    if (Object.keys(actual).length !== keys.length || keys.some((k) => actual[k] !== expected[k])) fail(code);
  }
  if (Number(await call('DBSIZE')) !== 2) fail('store-not-fresh');
  const snapshot = await call(...SNAP(m));
  let parsed;
  try { parsed = parseSnapshotReply(snapshot, m); } catch { return fail('snapshot-invalid'); }
  if (parsed.tag !== 'SNAPSHOT') fail('snapshot-invalid');
  if (gatewayUsername !== undefined) {
    if (!ACL_USER.test(gatewayUsername)) fail('acl-invalid');
    // A missing user makes DRYRUN itself error; that is an invalid account, not an uncertain transport.
    const dry = async (cmd: (string | number)[]) => { try { return await io.call('ACL', 'DRYRUN', gatewayUsername, ...cmd); } catch { return fail('acl-invalid'); } };
    for (const cmd of ACL_ALLOW) if ((await dry(cmd)) !== 'OK') fail('acl-invalid');
    for (const cmd of ACL_DENY) if ((await dry(cmd)) === 'OK') fail('acl-invalid');
  }
}
