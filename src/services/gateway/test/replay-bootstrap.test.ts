// Pure (no Redis) checks of the public bootstrap artifact; behavior against a real Redis is in redis-adapter-redis.test.ts.
import test from 'node:test';
import assert from 'node:assert/strict';
import golden from '../../../contracts/fixtures/policy-golden.json' with { type: 'json' };
import { makeManifest, configurationDigest } from '../../../contracts/lib/index.ts';
import {
  GATEWAY_ACL_RULES, REPLAY_BOOTSTRAP_REVISION, REPLAY_INITIALIZER, REPLAY_SCRIPTS, gatewayAclArgs, initialStoreState, initializeStore,
  installGatewayAcl, loadReplayScripts, parseRedisTime, policyIdentity, readRunStart, verifyStoreReady, type RedisIo,
} from '../../../contracts/lib/replay.ts';
import { REPLAY_SCRIPTS as GATEWAY_VIEW } from '../src/replay-scripts.ts';

const manifest = () => makeManifest({ run_id: golden.manifest.run_id, run_start_ms: 1793000000123, token_key_spki_b64url: golden.manifest.token_key_spki_b64url,
  snapshot_script_sha1: REPLAY_SCRIPTS.snapshot.sha1, claim_script_sha1: REPLAY_SCRIPTS.claim.sha1 });
const reason = (r: string) => (e: unknown) => e instanceof Error && e.message === `replay-bootstrap-${r}`;
const recording = (reply: (c: string, a: unknown[]) => unknown) => { const calls: unknown[][] = []; const io: RedisIo = { call: async (c, ...a) => { calls.push([c, ...a]); return reply(c, a); } }; return { io, calls }; };

test('one authoritative Lua implementation: the gateway re-exports the shared one with the reviewed hashes', () => {
  assert.equal(GATEWAY_VIEW, REPLAY_SCRIPTS);
  assert.equal(REPLAY_SCRIPTS.snapshot.sha1, '20b8aa1866d30e41364acb05826a5617d27f1c72');
  assert.equal(REPLAY_SCRIPTS.claim.sha1, 'c4a37fc975fe7f68e73c1e0d47b4c1779a182784');
  assert.match(REPLAY_INITIALIZER.sha1, /^[0-9a-f]{40}$/);
  assert.equal(REPLAY_BOOTSTRAP_REVISION, 'replay-bootstrap-1');
  assert.ok(Object.isFrozen(REPLAY_SCRIPTS));
});

test('initial state is exactly eight policy fields and four clock fields with the manifest identity', () => {
  const m = manifest(); const s = initialStoreState(m);
  assert.deepEqual(Object.keys(s.policy), ['schema_version', 'run_id', 'token_type', 'token_key_id', 'config_digest', 'run_start_ms', 'epoch_ms', 'guard_ms']);
  assert.deepEqual(Object.keys(s.clock), ['run_id', 'last_now_ms', 'highest_epoch', 'closed']);
  assert.deepEqual(s.policy, { schema_version: '1', run_id: m.run_id, token_type: '2', token_key_id: m.token_key_id, config_digest: configurationDigest(m),
    run_start_ms: '1793000000123', epoch_ms: '600000', guard_ms: '30000' });
  assert.deepEqual(s.clock, { run_id: m.run_id, last_now_ms: '1793000000123', highest_epoch: '0', closed: '0' });
  assert.deepEqual(policyIdentity(m), [m.run_id, m.token_key_id, configurationDigest(m)]);
});

test('the gateway account grants only what the scripts and the pinned client use', () => {
  const rules: string[] = [...GATEWAY_ACL_RULES];
  assert.deepEqual(rules.filter((r) => r.startsWith('~')), ['~pp:policy', '~pp:clock', '~pp:spent:*']);
  assert.equal(rules[rules.indexOf('-@all')], '-@all');
  assert.ok(rules.slice(rules.indexOf('-@all') + 1).every((r) => /^\+[a-z|]+$/.test(r)));
  for (const forbidden of ['+eval', '+script', '+config', '+acl', '+flushdb', '+flushall', '+keys', '+del', '+@all', '+shutdown', '+debug', '+client']) assert.ok(!rules.includes(forbidden), forbidden);
  const args = gatewayAclArgs('gateway', 'x'.repeat(40));
  assert.deepEqual(args.slice(0, 4), ['SETUSER', 'gateway', 'reset', 'on']);
  assert.equal(args[4], '>' + 'x'.repeat(40));
});

test('ACL arguments reject weak passwords, odd or default usernames, and never echo the password', async () => {
  for (const [u, p] of [['default', 'p'.repeat(40)], ['', 'p'.repeat(40)], ['a b', 'p'.repeat(40)], ['gateway', 'short'], ['gateway', 'has space '.repeat(5)], ['gateway', 'p'.repeat(300)]]) {
    assert.throws(() => gatewayAclArgs(u!, p!), reason('acl-invalid'));
  }
  const secret = 'K'.repeat(48);
  const { io } = recording(() => { throw new Error('boom ' + secret); });
  await assert.rejects(installGatewayAcl(io, 'gateway', secret), (e: Error) => e.message === 'replay-bootstrap-uncertain' && !JSON.stringify(e).includes(secret));
  await assert.rejects(installGatewayAcl(recording(() => 'WRONG').io, 'gateway', secret), reason('acl-invalid'));
});

test('Redis TIME parsing is canonical and bounded', () => {
  assert.equal(parseRedisTime(['1793000000', '123456']), 1793000000123);
  assert.equal(parseRedisTime(['1', '999999']), 1999);
  for (const bad of [undefined, null, 'x', [], ['1'], ['1', '2', '3'], ['01', '5'], ['+1', '5'], ['1', '1000000'], ['1', '05'], ['9007199254741', '0'], [1.5, 0], [-1, 0], [Number.NaN, 0]]) {
    assert.throws(() => parseRedisTime(bad), reason('time-invalid'), JSON.stringify(bad));
  }
});

test('transport failures and unexpected replies are uncertain, never success, and nothing is retried', async () => {
  const lost = recording(() => { throw new Error('connection lost'); });
  await assert.rejects(readRunStart(lost.io), reason('uncertain'));
  await assert.rejects(loadReplayScripts(lost.io), reason('uncertain'));
  await assert.rejects(initializeStore(lost.io, manifest()), reason('uncertain'));
  await assert.rejects(verifyStoreReady(lost.io, manifest()), reason('uncertain'));
  assert.equal(lost.calls.length, 4, 'exactly one attempt each');
  await assert.rejects(loadReplayScripts(recording(() => '0'.repeat(40)).io), reason('script-mismatch'));
  for (const odd of [null, 'OK', [], ['INITIALIZED', 'extra'], ['SOMETHING']]) await assert.rejects(initializeStore(recording(() => odd).io, manifest()), reason('uncertain'), JSON.stringify(odd));
  await assert.rejects(initializeStore(recording(() => ['NOT_EMPTY']).io, manifest()), reason('store-not-empty'));
  await assert.rejects(initializeStore(recording(() => ['CLOCK_UNSAFE']).io, manifest()), reason('clock-unsafe'));
  await assert.rejects(initializeStore(recording(() => ['INVALID']).io, manifest()), reason('invalid-arguments'));
  const ok = recording(() => ['INITIALIZED']);
  await initializeStore(ok.io, manifest());
  assert.equal(ok.calls.length, 1);
  assert.deepEqual(ok.calls[0]!.slice(0, 5), ['EVALSHA', REPLAY_INITIALIZER.sha1, 2, 'pp:policy', 'pp:clock']);
});

test('the manifest is validated before anything is sent', async () => {
  const never = recording(() => { throw new Error('must not be called'); });
  await assert.rejects(initializeStore(never.io, { nonsense: true }), reason('manifest-invalid'));
  await assert.rejects(initializeStore(never.io, { ...manifest(), claim_script_sha1: '3'.repeat(40) }), reason('script-mismatch'));
  await assert.rejects(verifyStoreReady(never.io, { ...manifest(), snapshot_script_sha1: '4'.repeat(40) }), reason('script-mismatch'));
  assert.equal(never.calls.length, 0);
});
