import test, { before, after, afterEach, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { Redis } from 'ioredis';
import { publicVerif, TokenChallenge, WWWAuthenticateHeader } from '@cloudflare/privacypass-ts';
import { createServer } from 'node:http';
import { connect, type Socket } from 'node:net';
import { once } from 'node:events';
import golden from '../../../contracts/fixtures/policy-golden.json' with { type: 'json' };
import { configurationDigest, makeManifest, encodeBase64Url, redemptionContext, spendId, challengeBytes, type Manifest } from '../../../contracts/lib/index.ts';
import { REPLAY_SCRIPTS } from '../src/replay-scripts.ts';
import { openRedisReplayStore } from '../src/redis-adapter.ts';
import { ReplayStore, type ReplayConnection, type ReplayFault } from '../src/replay-store.ts';
import { WorkerLease } from '../src/worker-lease.ts';
import { FixedOrigin, type OriginRuntime } from '../src/fixed-origin.ts';
import { RequestCoordinator, type CoordinatorResponse, type RequestView } from '../src/request-coordinator.ts';

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

type ReplayView = Parameters<typeof RequestCoordinator.prepare>[2];
function replayView(store: ReplayStore): ReplayView {
  return { binding: store.binding, get status() { return store.status; }, signal: store.signal,
    snapshot: () => store.snapshot(), claim: c => store.claim(c), close: () => store.close() };
}
async function flow(t: TestContext, nearBoundary = false) {
  const mode = publicVerif.BlindRSAMode.PSS;
  const keys = await publicVerif.Issuer.generateKey(mode, { modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) });
  const spki = await publicVerif.getPublicKeyBytes(keys.publicKey);
  await seed();
  const time = await admin.time(), now = Number(time[0]) * 1000 + Math.floor(Number(time[1]) / 1000);
  m = makeManifest({ run_id: m.run_id, run_start_ms: now - (nearBoundary ? 595000 : 300000),
    token_key_spki_b64url: encodeBase64Url(spki), snapshot_script_sha1: REPLAY_SCRIPTS.snapshot.sha1, claim_script_sha1: REPLAY_SCRIPTS.claim.sha1 });
  const manifest = m;
  await admin.hset('pp:policy', 'token_key_id', m.token_key_id, 'config_digest', configurationDigest(m), 'run_start_ms', String(m.run_start_ms));
  await admin.hset('pp:clock', 'last_now_ms', String(m.run_start_ms));
  const store = await open();
  const ids = { worker_incarnation: '1'.repeat(32), supervisor_incarnation: '2'.repeat(32) };
  const lease = WorkerLease.prepare(m, ids, () => {});
  let received = 0; const sockets = new Set<Socket>();
  const server = createServer((req, res) => {
    if (req.url === '/resource') received++; // Independent arrival count BEFORE generation validation.
    if (req.headers['x-tokenforge-run'] !== manifest.run_id) { res.writeHead(409).end(); return; }
    res.end('protected resource');
  });
  server.keepAliveTimeout = 20000;
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); const port = (server.address() as { port: number }).port;
  const runtime: OriginRuntime = { nowNs: () => process.hrtime.bigint(),
    schedule(ms, fn) { const timer = setTimeout(fn, ms); return () => clearTimeout(timer); },
    connect: () => connect({ host: '127.0.0.1', port }) };
  const origin = FixedOrigin.prepare(manifest, lease, runtime);
  let coordinator: RequestCoordinator | undefined, seq = 0;
  const heartbeat = setInterval(() => {
    if (lease.status.state !== 'ENABLED') return;
    const stamp = process.hrtime.bigint();
    lease.heartbeat({ version: 1, run_id: manifest.run_id, config_digest: configurationDigest(manifest), ...ids,
      sequence: ++seq, issued_at_ns: String(stamp), expires_at_ns: String(stamp + 3000000000n) });
  }, 1000);
  t.after(async () => {
    clearInterval(heartbeat); lease.fence(); if (coordinator) await coordinator.close(); await origin.close();
    server.close(); for (const socket of sockets) socket.destroy();
  });
  async function start(replay: ReplayView = replayView(store)) {
    coordinator = await RequestCoordinator.prepare(manifest, lease, replay, origin);
    const stamp = process.hrtime.bigint();
    assert.equal(lease.enable({ version: 1, run_id: manifest.run_id, config_digest: configurationDigest(manifest), ...ids,
      sequence: 0, issued_at_ns: String(stamp), expires_at_ns: String(stamp + 3000000000n) }), true);
    return coordinator;
  }
  async function token(wrongOrigin = false) {
    const client = new publicVerif.Client(mode);
    const request = await client.createTokenRequest(new TokenChallenge(2, manifest.issuer_name, redemptionContext(manifest, 0),
      [wrongOrigin ? 'other.lab.test' : manifest.origin_name]), spki);
    return (await client.finalize(await new publicVerif.Issuer(mode, manifest.issuer_name, keys.privateKey, keys.publicKey).issue(request))).serialize();
  }
  function view(wire?: Uint8Array, signal = new AbortController().signal): RequestView {
    return { method: 'GET', target: '/resource', hasBody: false, signal,
      rawHeaders: ['Host', manifest.origin_name, ...(wire ? ['Authorization', `PrivateToken token="${encodeBase64Url(wire)}"`] : [])] };
  }
  async function run(v: RequestView) {
    const results: CoordinatorResponse[] = [];
    await coordinator!.handle(v, async response => { results.push(response); }); return results;
  }
  return { manifest, store, lease, origin, runtime, port, token, view, run, start, received: () => received };
}

test('coordinator real blind issuance, concurrent redemption and replay yield exactly one origin arrival', async t => {
  const f = await flow(t), wire = await f.token(); let snapshots = 0;
  const replay = replayView(f.store), original = replay.snapshot;
  replay.snapshot = () => { snapshots++; return original(); };
  await f.start(replay);
  const replies = (await Promise.all([f.run(f.view(wire)), f.run(f.view(wire))])).flat();
  assert.equal(replies.filter(r => r.status === 200).length, 1);
  assert.equal(replies.filter(r => r.status === 401).length, 1);
  const rejected = replies.find(r => r.status === 401)!;
  assert.ok('headers' in rejected && rejected.headers['www-authenticate']);
  assert.equal(snapshots, 3); // Context snapshot per token + NEW challenge snapshot for final replay401.
  assert.equal(f.received(), 1);
  assert.equal((await admin.keys('pp:spent:*')).length, 1);
});

test('coordinator rejects missing, forged and genuine wrong-context tokens without origin arrivals or spending', async t => {
  const f = await flow(t), wire = await f.token(), wrong = await f.token(true); await f.start();
  const forged = wire.slice(); forged[2] = forged[2]! ^ 1;
  for (const input of [undefined, forged, wrong]) {
    const replies = await f.run(f.view(input)); assert.equal(replies[0]!.status, 401);
    assert.ok('headers' in replies[0]! && replies[0]!.headers['www-authenticate']);
  }
  assert.equal(f.received(), 0); assert.equal((await admin.keys('pp:spent:*')).length, 0);
});

test('coordinator cancellation after a real committed claim keeps the token spent and never forwards', async t => {
  const f = await flow(t), wire = await f.token(), client = new AbortController();
  const replay = replayView(f.store); replay.claim = async c => { const result = await f.store.claim(c); client.abort(); return result; };
  await f.start(replay);
  assert.deepEqual(await f.run(f.view(wire, client.signal)), []);
  assert.equal(f.received(), 0); assert.equal(await admin.exists(`pp:spent:${spendId(wire.subarray(0, 98))}`), 1);
});

test('coordinator uncertain committed claim closes the lease, produces no challenge and never forwards', async t => {
  const f = await flow(t), wire = await f.token();
  const replay = replayView(f.store); replay.claim = async c => { await f.store.claim(c); f.store.close(); return { kind: 'unavailable' }; };
  await f.start(replay); const replies = await f.run(f.view(wire));
  assert.equal(replies[0]!.status, 503); assert.ok('headers' in replies[0]! && !replies[0]!.headers['www-authenticate']);
  assert.equal(f.lease.status.run_closed, true); assert.equal(f.received(), 0);
  assert.equal(await admin.exists(`pp:spent:${spendId(wire.subarray(0, 98))}`), 1);
});

test('coordinator epoch closes between snapshot and claim and final401 carries the new epoch challenge', async t => {
  const f = await flow(t, true), wire = await f.token();
  const replay = replayView(f.store);
  replay.claim = async c => {
    for (;;) {
      const time = await admin.time();
      if (Number(time[0]) * 1000 + Math.floor(Number(time[1]) / 1000) >= f.manifest.run_start_ms + 600000) break;
      await delay(20);
    }
    return f.store.claim(c);
  };
  await f.start(replay); const replies = await f.run(f.view(wire));
  assert.equal(replies[0]!.status, 401); assert.ok('body' in replies[0]! && String(replies[0]!.body).includes('token-expired'));
  assert.ok('headers' in replies[0]! && replies[0]!.headers['www-authenticate']);
  if ('headers' in replies[0]!) {
    const parsed = WWWAuthenticateHeader.parse(replies[0]!.headers['www-authenticate']!);
    assert.deepEqual(Uint8Array.from(parsed[0]!.challenge.serialize()), challengeBytes(f.manifest, 1));
  }
  assert.equal(f.received(), 0); assert.equal((await admin.keys('pp:spent:*')).length, 0);
});

test('coordinator idle Redis failure cancels a claimed delayed-connect flow and suppresses its late DNS callback', async t => {
  const f = await flow(t), wire = await f.token(); let complete!: () => void, entered!: () => void;
  const connecting = new Promise<void>(resolve => { entered = resolve; });
  f.runtime.connect = () => connect({ host: 'delayed.test', port: f.port, lookup(_host, _options, callback) {
    complete = () => callback(null, '127.0.0.1', 4); entered();
  } });
  await f.start(); const pending = f.run(f.view(wire)); await connecting;
  f.store.close(); assert.equal(f.lease.status.run_closed, true);
  assert.equal((await pending)[0]!.status, 503); complete(); await delay(20);
  assert.equal(f.received(), 0); assert.equal(f.origin.status.sockets, 0);
});
