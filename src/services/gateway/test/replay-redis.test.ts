import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import golden from '../../../contracts/fixtures/policy-golden.json' with { type: 'json' };
import { configurationDigest, makeManifest, parseSnapshotReply, parseClaimReply, type Manifest } from '../../../contracts/lib/index.ts';
import { REPLAY_SCRIPTS } from '../src/replay-scripts.ts';

// Test-only Redis 7.4.8. No host port, external network, data mount or persistence.
// The production server/ACL/client adapter is a separate integration milestone.
const image = 'redis@sha256:efc27681bf81e6ed55cb581718b7818c6c04c39b1f9aa40854edd3ea2241b6ed';
const exec = promisify(execFile);
let container = '';
async function docker(...args: string[]): Promise<string> {
  const { stdout } = await exec('docker', args, { encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024 });
  return stdout.trim();
}
async function command(...args: string[]): Promise<any> {
  const reply = await docker('exec', container, 'redis-cli', '--json', ...args);
  if (reply.startsWith('error:')) throw Error(`Redis test command failed: ${reply}`);
  return JSON.parse(reply);
}
before(async () => {
  container = await docker('run', '-d', '--rm', '--network', 'none', '--user', 'redis', '--read-only',
    '--tmpfs', '/data:rw,noexec,nosuid,size=8m', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    // Twenty concurrent docker-exec clients also need transient runc namespace-entry processes.
    // This is a test-harness budget only; production gateway limits are unchanged.
    '--memory', '384m', '--pids-limit', '128', '--log-driver', 'none', image, 'redis-server',
    '--bind', '127.0.0.1', '--save', '', '--appendonly', 'no', '--maxmemory', '268435456',
    '--maxmemory-policy', 'noeviction', '--slowlog-log-slower-than', '-1', '--slowlog-max-len', '0', '--acllog-max-len', '0');
  for (let attempt = 0; attempt < 30; attempt++) {
    try { if (await command('PING') === 'PONG') break; } catch { /* bounded startup only */ }
    if (attempt === 29) throw Error('Test Redis did not become ready');
    await delay(100);
  }
  for (const script of Object.values(REPLAY_SCRIPTS)) assert.equal(await command('SCRIPT', 'LOAD', script.source), script.sha1);
});
after(async () => { if (container) await docker('rm', '-f', container); });

let manifest: Manifest;
let identity: string[];
const digest = 'a'.repeat(64);
const spent = `pp:spent:${digest}`;
async function seed(mutation = '', offset = 0): Promise<void> {
  const time = await command('TIME');
  const now = Number(time[0]) * 1000 + Math.floor(Number(time[1]) / 1000);
  // Center within an epoch to avoid wall-clock sleeps and flaky boundaries.
  manifest = makeManifest({ run_id: golden.manifest.run_id, run_start_ms: now - 300000 + offset,
    token_key_spki_b64url: golden.manifest.token_key_spki_b64url,
    snapshot_script_sha1: REPLAY_SCRIPTS.snapshot.sha1, claim_script_sha1: REPLAY_SCRIPTS.claim.sha1 });
  identity = [manifest.run_id, manifest.token_key_id, configurationDigest(manifest)];
  // FLUSHDB is confined to this newly created, network-isolated TEST process.
  await command('EVAL', `redis.call('FLUSHDB')
    redis.call('HSET','pp:policy','schema_version','1','run_id',ARGV[1],'token_type','2','token_key_id',ARGV[2],
      'config_digest',ARGV[3],'run_start_ms',ARGV[4],'epoch_ms','600000','guard_ms','30000')
    redis.call('HSET','pp:clock','run_id',ARGV[1],'last_now_ms',ARGV[4],'highest_epoch','0','closed','0')
    ${mutation}
    return 'OK'`, '0', ...identity, String(manifest.run_start_ms));
}
async function snapshot(args = identity, keys = ['pp:policy', 'pp:clock']) {
  return command('EVALSHA', REPLAY_SCRIPTS.snapshot.sha1, String(keys.length), ...keys, ...args);
}
async function claim(epoch = '0', d = digest, key = `pp:spent:${d}`, args = identity) {
  return command('EVALSHA', REPLAY_SCRIPTS.claim.sha1, '3', 'pp:policy', 'pp:clock', key, ...args, epoch, d);
}
async function state() {
  return command('EVAL', "return {redis.call('HGETALL','pp:policy'),redis.call('HGETALL','pp:clock'),redis.call('DBSIZE')}", '0');
}

test('snapshot uses real Redis time, echoes the frozen ABI, and is read-only', async () => {
  await seed();
  const before = await state();
  const reply = await snapshot();
  assert.equal(parseSnapshotReply(reply, manifest).tag, 'SNAPSHOT');
  assert.equal(reply[5], 0);
  assert.deepEqual(await state(), before);
  assert.equal(await command('PTTL', 'pp:policy'), -1);
  assert.equal(await command('PTTL', 'pp:clock'), -1);
});

test('twenty independent concurrent Redis invocations produce one claim and nineteen replays', async () => {
  await seed();
  const replies = await Promise.all(Array.from({ length: 20 }, () => claim()));
  const expiry = manifest.run_start_ms + manifest.epoch_ms + manifest.guard_ms;
  replies.forEach(r => parseClaimReply(r, expiry));
  assert.equal(replies.filter(r => r[0] === 'CLAIMED').length, 1);
  assert.equal(replies.filter(r => r[0] === 'ALREADY_SPENT').length, 19);
  assert.equal(await command('GET', spent), '1');
  assert.equal(await command('PEXPIRETIME', spent), expiry);
  assert.equal(await command('DBSIZE'), 3);
  assert.equal(await command('HGET', 'pp:clock', 'highest_epoch'), '0');
  assert.ok(Number(await command('HGET', 'pp:clock', 'last_now_ms')) > manifest.run_start_ms);
});

test('a stale snapshot cannot authorize a claim in the next epoch', async () => {
  await seed('', -295000); // Epoch 0 ends in ~5 seconds, using real Redis TIME.
  const old = parseSnapshotReply(await snapshot(), manifest);
  assert.equal(old.epoch, 0);
  const deadline = performance.now() + 15000;
  let current = old;
  while (current.epoch === 0 && performance.now() < deadline) {
    await delay(100);
    current = parseSnapshotReply(await snapshot(), manifest);
  }
  assert.equal(current.epoch, 1);
  assert.deepEqual(await claim(String(old.epoch)), ['EPOCH_CLOSED']);
  assert.equal(await command('EXISTS', spent), 0);
  assert.deepEqual(await claim('1'), ['CLAIMED', manifest.run_start_ms + 1200000 + 30000]);
  assert.equal(await command('HGET', 'pp:clock', 'highest_epoch'), '1');
});

test('identity, exact argument/key names and canonical candidate/digest encodings are mandatory', async () => {
  await seed();
  const before = await state();
  for (let index = 0; index < 3; index++) {
    const wrong = [...identity]; wrong[index] = 'f'.repeat(index === 0 ? 32 : 64);
    assert.deepEqual(await snapshot(wrong), ['RUN_UNAVAILABLE']);
    assert.deepEqual(await claim('0', digest, spent, wrong), ['RUN_UNAVAILABLE']);
  }
  for (const epoch of ['00', '-1', '1e0', '0.0', ' 0', '9007199254740992']) assert.deepEqual(await claim(epoch), ['RUN_UNAVAILABLE']);
  for (const d of ['A'.repeat(64), 'a'.repeat(63), 'g'.repeat(64)]) assert.deepEqual(await claim('0', d), ['RUN_UNAVAILABLE']);
  assert.deepEqual(await claim('0', digest, 'other:' + digest), ['RUN_UNAVAILABLE']);
  assert.deepEqual(await snapshot(identity, ['pp:policy', 'pp:clock', 'extra']), ['RUN_UNAVAILABLE']);
  assert.deepEqual(await snapshot([...identity, 'extra']), ['RUN_UNAVAILABLE']);
  assert.deepEqual(await snapshot(identity, ['other', 'pp:clock']), ['RUN_UNAVAILABLE']);
  assert.deepEqual(await state(), before);
});

test('missing, mistyped, expiring, altered and noncanonical guards fail without repair or spending', async () => {
  const faults = [
    "redis.call('DEL','pp:policy')", "redis.call('DEL','pp:clock')",
    "redis.call('DEL','pp:policy');redis.call('SET','pp:policy','wrong')",
    "redis.call('DEL','pp:clock');redis.call('LPUSH','pp:clock','wrong')",
    "redis.call('PEXPIRE','pp:policy',60000)", "redis.call('PEXPIRE','pp:clock',60000)",
    "redis.call('HSET','pp:policy','extra','1')", "redis.call('HDEL','pp:policy','token_type')",
    "redis.call('HSET','pp:policy','token_type','02')", "redis.call('HSET','pp:policy','schema_version','2')",
    "redis.call('HSET','pp:policy','epoch_ms','600001')", "redis.call('HSET','pp:policy','guard_ms','0')",
    "redis.call('HSET','pp:policy','run_start_ms','01')",
    "redis.call('HSET','pp:policy','run_start_ms','9007199254740992')",
    "redis.call('HSET','pp:policy','run_id','wrong')", "redis.call('HSET','pp:policy','token_key_id','wrong')",
    "redis.call('HSET','pp:policy','config_digest','wrong')",
    "redis.call('HSET','pp:clock','run_id','wrong')", "redis.call('HSET','pp:clock','extra','1')",
    "redis.call('HDEL','pp:clock','closed')", "redis.call('HSET','pp:clock','closed','1')",
    "redis.call('HSET','pp:clock','closed','00')", "redis.call('HSET','pp:clock','last_now_ms','-1')",
    "redis.call('HSET','pp:clock','highest_epoch','1e0')",
  ];
  for (const fault of faults) {
    await seed(fault);
    assert.deepEqual(await snapshot(), ['RUN_UNAVAILABLE'], fault);
    assert.deepEqual(await claim(), ['RUN_UNAVAILABLE'], fault);
    assert.equal(await command('EXISTS', spent), 0, fault);
  }
});

test('recorded clock regression, inconsistent highwater and future run start fail closed', async () => {
  for (const fault of [
    "redis.call('HSET','pp:clock','last_now_ms',string.format('%.0f',tonumber(ARGV[4])+400000))",
    "redis.call('HSET','pp:clock','last_now_ms',string.format('%.0f',tonumber(ARGV[4])-1))",
    "redis.call('HSET','pp:clock','highest_epoch','1')",
  ]) {
    await seed(fault);
    const before = await state();
    assert.deepEqual(await snapshot(), ['CLOCK_UNSAFE']);
    assert.deepEqual(await claim(), ['CLOCK_UNSAFE']);
    assert.deepEqual(await state(), before);
  }
  await seed('', 600000);
  assert.deepEqual(await snapshot(), ['CLOCK_UNSAFE']);
  assert.deepEqual(await claim(), ['CLOCK_UNSAFE']);
});

test('unexpected spent type, value, persistent key or wrong absolute deadline is unsafe', async () => {
  for (const mutation of [
    `redis.call('LPUSH','${spent}','1')`, `redis.call('SET','${spent}','2')`,
    `redis.call('SET','${spent}','1')`, `redis.call('SET','${spent}','1','PX',120000)`,
  ]) {
    await seed(mutation);
    const before = await state();
    assert.deepEqual(await claim(), ['RUN_UNAVAILABLE']);
    assert.deepEqual(await state(), before);
  }
});

test('a lost successful response does not refund the claim; a second invocation is replay', async () => {
  await seed();
  await claim(); // Test deliberately discards the result AFTER the real commit.
  assert.deepEqual(await claim(), ['ALREADY_SPENT']);
  assert.equal(await command('GET', spent), '1');
});

test('missing script returns NOSCRIPT and does not recreate guards or spend state', async () => {
  await seed();
  await command('SCRIPT', 'FLUSH');
  await assert.rejects(() => snapshot(), /NOSCRIPT/);
  assert.equal(await command('DBSIZE'), 2);
  // No live reload: the isolated TEST process ends after this final test.
});
