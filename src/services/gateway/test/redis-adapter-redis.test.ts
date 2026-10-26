import test, { before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { Redis } from 'ioredis';
import golden from '../../../contracts/fixtures/policy-golden.json' with { type: 'json' };
import { configurationDigest, makeManifest, type Manifest } from '../../../contracts/lib/index.ts';
import { REPLAY_SCRIPTS } from '../src/replay-scripts.ts';
import { openRedisReplayStore } from '../src/redis-adapter.ts';
import { ReplayStore, type ReplayConnection, type ReplayFault } from '../src/replay-store.ts';

// Executed ONLY in a disposable container sharing an isolated Redis network
// namespace. No host port, Docker socket, credentials file or external network.
const admin = new Redis({ host: '127.0.0.1', port: 6379, protocol: 2, lazyConnect: true,
  enableReadyCheck: false, disableClientInfo: true, retryStrategy: () => null });
admin.on('error', () => {});
const endpoint = { host: '127.0.0.1', port: 6379, username: 'gateway', password: randomBytes(32).toString('hex') };
const stores: ReplayStore[] = [];
const faults: ReplayFault[] = [];
let m: Manifest;
const candidate = () => ({ kind: 'claim-candidate', epoch: 0, spend_id: 'a'.repeat(64) });
before(async () => {
  await admin.connect();
  await admin.acl('SETUSER', 'gateway', 'reset', 'on', `>${endpoint.password}`,
    '~pp:policy', '~pp:clock', '~pp:spent:*', '-@all',
    '+auth', '+type', '+pttl', '+hlen', '+hmget', '+time', '+get', '+pexpiretime', '+hset', '+set',
    '+evalsha', '+script|exists');
});
afterEach(() => { for (const store of stores.splice(0)) store.close(); });
after(() => admin.disconnect(false));
async function seed(mutation?: () => Promise<unknown>) {
  faults.length = 0;
  await admin.flushdb(); // This isolated TEST server never hosts an active deployment.
  for (const script of Object.values(REPLAY_SCRIPTS)) assert.equal(await admin.script('LOAD', script.source), script.sha1);
  const time = await admin.time();
  const now = Number(time[0]) * 1000 + Math.floor(Number(time[1]) / 1000);
  m = makeManifest({ run_id: golden.manifest.run_id, run_start_ms: now - 300000,
    token_key_spki_b64url: golden.manifest.token_key_spki_b64url,
    snapshot_script_sha1: REPLAY_SCRIPTS.snapshot.sha1, claim_script_sha1: REPLAY_SCRIPTS.claim.sha1 });
  await admin.hset('pp:policy', { schema_version: '1', run_id: m.run_id, token_type: '2', token_key_id: m.token_key_id,
    config_digest: configurationDigest(m), run_start_ms: String(m.run_start_ms), epoch_ms: '600000', guard_ms: '30000' });
  await admin.hset('pp:clock', { run_id: m.run_id, last_now_ms: String(m.run_start_ms), highest_epoch: '0', closed: '0' });
  if (mutation) await mutation();
}
async function open() {
  const store = await openRedisReplayStore(m, endpoint, reason => { faults.push(reason); });
  stores.push(store); return store;
}

test('actual restricted-ACL driver prepares two connections, takes snapshots and permits one claim', async () => {
  await seed();
  const store = await open();
  const clients = (await admin.client('LIST') as string).split('\n').filter(line => line.includes('user=gateway'));
  assert.equal(clients.length, 2);
  const snapshot = await store.snapshot(); assert.equal(snapshot.kind, 'snapshot');
  if (snapshot.kind === 'snapshot') assert.equal(snapshot.epoch, 0);
  const replies = await Promise.all([store.claim(candidate()), store.claim(candidate())]);
  assert.equal(replies.filter(r => r.kind === 'claimed').length, 1);
  assert.equal(replies.filter(r => r.kind === 'rejected' && r.reason === 'token-already-redeemed').length, 1);
  assert.equal(await admin.pexpiretime(`pp:spent:${candidate().spend_id}`), m.run_start_ms + m.epoch_ms + m.guard_ms);
  assert.deepEqual(faults, []);
});

test('restricted gateway ACL cannot load scripts, reset data or administer Redis', async () => {
  const c = new Redis({ ...endpoint, protocol: 2, lazyConnect: true, enableReadyCheck: false, disableClientInfo: true, retryStrategy: () => null });
  c.on('error', () => {});
  await c.connect();
  try {
    for (const [cmd, args] of [['SCRIPT', ['LOAD', 'return 1']], ['FLUSHDB', []], ['CONFIG', ['GET', '*']], ['ACL', ['LIST']]] as const) {
      await assert.rejects(() => c.call(cmd, ...args), /NOPERM/);
    }
  } finally { c.disconnect(false); }
});

test('startup rejects altered run_start despite unchanged stored digest, and never repairs missing guards', async () => {
  await seed(async () => admin.hset('pp:policy', 'run_start_ms', String(m.run_start_ms + 1)));
  await assert.rejects(open, /replay-preparation-failed/);
  assert.equal(await admin.hget('pp:policy', 'run_start_ms'), String(m.run_start_ms + 1));
  await seed(async () => admin.del('pp:clock'));
  await assert.rejects(open, /replay-preparation-failed/);
  assert.equal(await admin.exists('pp:clock'), 0);
});

test('runtime script loss closes the pool; reloading scripts cannot revive that store', async () => {
  await seed(); const store = await open();
  await admin.script('FLUSH');
  assert.deepEqual(await store.claim(candidate()), { kind: 'unavailable' });
  assert.equal(store.status.state, 'closed'); assert.equal(faults.length, 1);
  for (const script of Object.values(REPLAY_SCRIPTS)) await admin.script('LOAD', script.source);
  assert.deepEqual(await store.claim(candidate()), { kind: 'unavailable' });
  assert.equal(await admin.exists(`pp:spent:${candidate().spend_id}`), 0);
});

test('runtime guard corruption and recorded clock regression close access without spending', async () => {
  for (const clockFault of [false, true]) {
    await seed(); const store = await open();
    if (clockFault) await admin.hset('pp:clock', 'last_now_ms', String(m.run_start_ms + 400000));
    else await admin.hset('pp:policy', 'guard_ms', '1');
    assert.deepEqual(await store.claim(candidate()), { kind: 'unavailable' });
    assert.equal(store.status.fault, clockFault ? 'clock-unsafe' : 'unsafe-state');
    assert.equal(await admin.exists(`pp:spent:${candidate().spend_id}`), 0);
  }
});

test('server pause exceeds fixed command deadline, destroys the pool and does not queue a claim', async () => {
  await seed(); const store = await open();
  await admin.client('PAUSE', '700', 'ALL');
  assert.deepEqual(await store.snapshot(), { kind: 'unavailable' });
  // Deadline safety must survive delayed scheduling; elapsed response latency
  // under host contention is not itself a performance guarantee.
  assert.equal(store.status.state, 'closed');
  await delay(750); // Test-only server pause ends; no application command is retried.
  assert.deepEqual(await store.claim(candidate()), { kind: 'unavailable' });
  assert.equal(await admin.exists(`pp:spent:${candidate().spend_id}`), 0);
  assert.deepEqual(faults, ['dependency-lost']);
});

test('real socket loss on one connection closes both; later availability never reconnects them', async () => {
  await seed(); const store = await open();
  const clients = (await admin.client('LIST') as string).split('\n').filter(line => line.includes('user=gateway'));
  const id = /(?:^| )id=(\d+)/.exec(clients[0]!)?.[1]; assert.ok(id);
  assert.equal(await admin.client('KILL', 'ID', id), 1);
  for (let i = 0; store.status.state !== 'closed' && i < 50; i++) await delay(10);
  assert.equal(store.status.state, 'closed');
  await delay(300);
  assert.deepEqual(await store.snapshot(), { kind: 'unavailable' });
  assert.equal((await admin.client('LIST') as string).split('\n').filter(line => line.includes('user=gateway')).length, 0);
  assert.deepEqual(faults, ['dependency-lost']);
});

test('real claim committed then reply discarded at a test-only seam closes the store without refund/retry', async () => {
  await seed();
  let claims = 0;
  class DiscardReply implements ReplayConnection {
    client = new Redis({ ...endpoint, protocol: 2, lazyConnect: true, enableReadyCheck: false, disableClientInfo: true, retryStrategy: () => null });
    async connect() { await this.client.connect(); }
    onLoss(fn: () => void) { this.client.on('error', fn).on('close', fn).on('end', fn); }
    close() { this.client.disconnect(false); this.client.stream?.destroy(); }
    async call(cmd: string, ...args: (string | number)[]) {
      const reply = await this.client.call(cmd, ...args);
      if (cmd === 'EVALSHA' && args[0] === REPLAY_SCRIPTS.claim.sha1) {
        claims++;
        return new Promise<never>(() => {}); // Deliberate fault injection AFTER real Redis commit.
      }
      return reply;
    }
  }
  const store = await ReplayStore.prepare(m, [new DiscardReply(), new DiscardReply()], reason => { faults.push(reason); });
  stores.push(store);
  assert.deepEqual(await store.claim(candidate()), { kind: 'unavailable' });
  assert.equal(await admin.get(`pp:spent:${candidate().spend_id}`), '1');
  assert.deepEqual(await store.claim(candidate()), { kind: 'unavailable' });
  assert.equal(claims, 1); assert.deepEqual(faults, ['dependency-lost']);
});
