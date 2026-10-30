import { createHash } from 'node:crypto';
import { PROTOCOL } from '../../../contracts/lib/index.ts';

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
