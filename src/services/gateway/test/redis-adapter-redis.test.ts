import test, { before, after, afterEach, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { Redis } from 'ioredis';
import { publicVerif, TokenChallenge, WWWAuthenticateHeader } from '@cloudflare/privacypass-ts';
import { createServer } from 'node:http';
import { connect, type Socket } from 'node:net';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { unlink, lstat } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { request as httpsRequest, type RequestOptions } from 'node:https';
import { connect as tlsConnect } from 'node:tls';
import golden from '../../../contracts/fixtures/policy-golden.json' with { type: 'json' };
import { PROTOCOL, validateControlResponse, configurationDigest, makeManifest, encodeBase64Url, redemptionContext, spendId, challengeBytes, type Manifest } from '../../../contracts/lib/index.ts';
import { REPLAY_SCRIPTS } from '../src/replay-scripts.ts';
import {
  GATEWAY_ACL_RULES, REPLAY_INITIALIZER, initialStoreState, initializeStore, installGatewayAcl, policyIdentity, loadReplayScripts, parseRedisTime, readRunStart, verifyStoreReady,
} from '../../../contracts/lib/replay.ts';
import { openRedisReplayStore } from '../src/redis-adapter.ts';
import { ReplayStore, type ReplayConnection, type ReplayFault } from '../src/replay-store.ts';
import { WorkerLease, type LeaseRuntime } from '../src/worker-lease.ts';
import { FixedOrigin, type OriginRuntime } from '../src/fixed-origin.ts';
import { RequestCoordinator, type CoordinatorResponse, type RequestView } from '../src/request-coordinator.ts';
import { HttpsGateway, type GatewayTls } from '../src/https-gateway.ts';

// Executed ONLY in a disposable container sharing an isolated Redis network
// namespace. No host port, Docker socket, credentials file or external network.
const admin = new Redis({ host: '127.0.0.1', port: 6379, protocol: 2, lazyConnect: true,
  enableReadyCheck: false, disableClientInfo: true, retryStrategy: () => null });
admin.on('error', () => {});
let testTls: GatewayTls;
try {
  testTls = JSON.parse(readFileSync(0, 'utf8')) as GatewayTls;
  if (typeof testTls.key !== 'string' || typeof testTls.cert !== 'string') throw Error();
} catch { throw Error('test-tls-input-invalid'); }
const endpoint = { host: '127.0.0.1', port: 6379, username: 'gateway', password: randomBytes(32).toString('hex') };
const io = { call: (command: string, ...args: (string | number)[]) => admin.call(command, ...args) };
const stores: ReplayStore[] = [];
const faults: ReplayFault[] = [];
let m: Manifest;
const candidate = () => ({ kind: 'claim-candidate', epoch: 0, spend_id: 'a'.repeat(64) });
before(async () => {
  await admin.connect();
  await installGatewayAcl(io, endpoint.username, endpoint.password); // the shared artifact, not a private copy
});
afterEach(() => { for (const store of stores.splice(0)) store.close(); });
after(() => admin.disconnect(false));
async function seed(mutation?: () => Promise<unknown>) {
  faults.length = 0;
  await admin.flushdb(); // This isolated TEST server never hosts an active deployment.
  await loadReplayScripts(io);
  const now = await readRunStart(io);
  m = makeManifest({ run_id: golden.manifest.run_id, run_start_ms: now - 300000,
    token_key_spki_b64url: golden.manifest.token_key_spki_b64url,
    snapshot_script_sha1: REPLAY_SCRIPTS.snapshot.sha1, claim_script_sha1: REPLAY_SCRIPTS.claim.sha1 });
  await initializeStore(io, m); // one atomic, empty-store-only initializer
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
  async function token(wrongOrigin: boolean | TokenChallenge = false) {
    const client = new publicVerif.Client(mode);
    const challenge = typeof wrongOrigin === 'boolean' ? new TokenChallenge(2, manifest.issuer_name, redemptionContext(manifest, 0),
      [wrongOrigin ? 'other.lab.test' : manifest.origin_name]) : wrongOrigin;
    const request = await client.createTokenRequest(challenge, spki);
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

async function ingress(t: TestContext, f: Awaited<ReturnType<typeof flow>>, replay?: ReplayView, runtime?: LeaseRuntime) {
  const coordinator = await f.start(replay); const server = HttpsGateway.prepare(f.manifest, f.lease, coordinator, testTls, runtime);
  const address = await server.listen('127.0.0.1', 0); t.after(() => server.close());
  function get(wire?: Uint8Array, path = '/resource') {
    return new Promise<{ status: number; headers: import('node:http').IncomingHttpHeaders; body: Buffer }>((resolve, reject) => {
      const options: RequestOptions & { ALPNProtocols: string[] } = { host: '127.0.0.1', port: address.port, servername: f.manifest.origin_name, ca: testTls.cert,
        minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'], agent: false, path,
        headers: { Host: f.manifest.origin_name, ...(wire ? { Authorization: `PrivateToken token="${encodeBase64Url(wire)}"` } : {}) } };
      const req = httpsRequest(options, res => {
        const parts: Buffer[] = []; res.on('data', b => parts.push(b)); res.on('error', reject);
        res.once('end', () => resolve({ status: res.statusCode!, headers: res.headers, body: Buffer.concat(parts) }));
      });
      req.once('error', () => reject(Error('test-https-request-failed'))); req.end();
    });
  }
  async function raw(bytes: string) {
    const socket = tlsConnect({ host: '127.0.0.1', port: address.port, servername: f.manifest.origin_name, ca: testTls.cert,
      minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'] });
    socket.on('error', () => {}); await once(socket, 'secureConnect'); const parts: Buffer[] = [];
    socket.on('data', b => parts.push(b)); const closed = once(socket, 'close'); socket.write(bytes); await closed;
    return Buffer.concat(parts).toString();
  }
  return { server, get, raw };
}

test('real HTTPS challenge -> blind issuance -> concurrent single-spend redemption reaches origin once', async t => {
  const f = await flow(t), gateway = await ingress(t, f);
  const challenge = await gateway.get(); assert.equal(challenge.status, 401);
  const parsed = WWWAuthenticateHeader.parse(String(challenge.headers['www-authenticate']));
  assert.equal(encodeBase64Url(parsed[0]!.tokenKey), f.manifest.token_key_spki_b64url);
  const wire = await f.token(parsed[0]!.challenge);
  const results = await Promise.all([gateway.get(wire), gateway.get(wire)]);
  assert.deepEqual(results.map(r => r.status).sort(), [200, 401]); assert.equal(f.received(), 1);
  assert.equal(results.find(r => r.status === 200)!.body.toString(), 'protected resource');
  for (const result of results) assert.equal(result.headers.connection, 'close');
  assert.ok(results.find(r => r.status === 401)!.headers['www-authenticate']);
  assert.equal((await admin.keys('pp:spent:*')).length, 1);
});

test('real HTTPS rejected signatures/contexts/routes/framing have zero origin arrivals or spent tokens', async t => {
  const f = await flow(t), wire = await f.token(), wrong = await f.token(true), gateway = await ingress(t, f);
  const forged = wire.slice(); forged[2] = forged[2]! ^ 1;
  assert.equal((await gateway.get(forged)).status, 401); assert.equal((await gateway.get(wrong)).status, 401);
  assert.equal((await gateway.get(wire, '/resource?forbidden=1')).status, 404);
  const credential = `Authorization: PrivateToken token="${encodeBase64Url(wire)}"\r\n`;
  const duplicateHost = await gateway.raw(`GET /resource HTTP/1.1\r\nHost: origin.lab.test\r\nHost: other.test\r\n${credential}\r\n`);
  assert.match(duplicateHost, /^HTTP\/1.1 400/);
  const malformed = await gateway.raw(`GET /resource HTTP/1.1\r\nHost: origin.lab.test\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n${credential}\r\n`);
  assert.equal(malformed, ''); assert.equal(f.received(), 0); assert.equal((await admin.keys('pp:spent:*')).length, 0);
});

test('wildcard HTTPS listener isolates equal remote-port connections to different local addresses', async t => {
  const f = await flow(t), coordinator = await f.start();
  const gateway = HttpsGateway.prepare(f.manifest, f.lease, coordinator, testTls);
  const address = await gateway.listen('0.0.0.0', 0); t.after(() => gateway.close());
  const first = connect({ host: '127.0.0.1', port: address.port, localAddress: '127.0.0.1' });
  first.on('error', () => {}); await once(first, 'connect');
  const second = connect({ host: '127.0.0.2', port: address.port, localAddress: '127.0.0.1', localPort: first.localPort! });
  second.on('error', () => {}); await once(second, 'connect');
  t.after(() => { first.destroy(); second.destroy(); });
  assert.equal(first.localPort, second.localPort);
  for (let i = 0; gateway.status.sockets !== 2 && i < 50; i++) await delay(5);
  assert.equal(gateway.status.sockets, 2);
  async function challenge(raw: Socket) {
    const tls = tlsConnect({ socket: raw, servername: f.manifest.origin_name, ca: testTls.cert,
      minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'] });
    tls.on('error', () => {}); await once(tls, 'secureConnect'); const chunks: Buffer[] = [];
    tls.on('data', data => chunks.push(data)); const closed = once(tls, 'close');
    tls.write('GET /resource HTTP/1.1\r\nHost: origin.lab.test\r\n\r\n'); await closed;
    assert.match(Buffer.concat(chunks).toString(), /^HTTP\/1.1 401/);
  }
  // Finish the SECOND handshake first: the first accepted raw record must not be selected accidentally.
  await challenge(second); await delay(20); assert.equal(first.destroyed, false);
  await challenge(first); assert.equal(f.received(), 0);
});

for (const stage of ['before-claim', 'before-native-send'] as const) test(`HTTPS absolute deadline rejects ${stage} even when timers never run`, async t => {
  const f = await flow(t), wire = await f.token(); let offset = 0n;
  const runtime: LeaseRuntime = { nowNs: () => process.hrtime.bigint() + offset, schedule: () => () => {} };
  const replay = replayView(f.store), original = replay.snapshot;
  if (stage === 'before-claim') replay.snapshot = async () => {
    const result = await original(); offset = 5000000000n; return result;
  };
  else f.runtime.connect = () => connect({ host: 'delayed.test', port: f.port,
    lookup(_host, _options, callback) { offset = 5000000000n; callback(null, '127.0.0.1', 4); } });
  const gateway = await ingress(t, f, replay, runtime);
  await assert.rejects(() => gateway.get(wire), /test-https-request-failed/);
  // Client closure can precede native origin/handler cleanup; observe the actual drain.
  for (let i = 0; gateway.server.status.handlers && i < 100; i++) await delay(5);
  assert.equal(gateway.server.status.handlers, 0); assert.equal(f.received(), 0);
  assert.equal((await admin.keys('pp:spent:*')).length, stage === 'before-claim' ? 0 : 1);
  assert.equal(f.origin.status.sockets, 0); assert.equal(f.lease.status.state, 'ENABLED');
});

// Real production entry point, private Unix control, cluster shared handle and production DNS endpoints.
async function serving(t: TestContext, profile: 'B0' | 'B1' = 'B1') {
  const f = await flow(t), manifest = makeManifest({ ...f.manifest, gateway_profile: profile });
  await admin.hset('pp:policy', 'config_digest', configurationDigest(manifest));
  let arrivals = 0;
  const origin = createServer((req, res) => {
    if (req.url === '/resource') arrivals++;
    if (req.headers['x-tokenforge-run'] !== manifest.run_id) { res.writeHead(409).end(); return; }
    res.end('supervised resource');
  });
  origin.listen(8080, '127.0.0.1'); await once(origin, 'listening');
  const child = spawn(process.execPath, ['dist/serve.mjs'], { stdio: ['pipe', 'pipe', 'pipe'] });
  const exited = new Promise<void>(resolve => child.once('exit', () => resolve()));
  child.stdout.resume(); let diagnostic = ''; child.stderr.on('data', b => { diagnostic += b.toString(); });
  child.stdin.end(JSON.stringify({ tls: testTls, redis: { username: endpoint.username, password: endpoint.password }, listen_host: '127.0.0.1' }));
  const links = new Set<Socket>(); let knownWorkers: number[] = [];
  const workers = () => {
    try { return readFileSync(`/proc/${child.pid}/task/${child.pid}/children`, 'utf8').trim().split(/\s+/).filter(Boolean).map(Number); }
    catch { return []; }
  };
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) { child.kill('SIGCONT'); child.kill('SIGTERM'); }
    await exited;
    for (const socket of links) socket.destroy();
    // All recorded PIDs were observed as children of our exact spawned supervisor. Never inspect/kill unrelated processes.
    const running = (pid: number) => {
      try { const stat = readFileSync(`/proc/${pid}/stat`, 'utf8'); return stat.slice(stat.lastIndexOf(')') + 2).split(' ')[0] !== 'Z'; }
      catch { return false; }
    };
    for (let i = 0; i < 150 && knownWorkers.some(running); i++) await delay(20);
    assert.ok(knownWorkers.every(pid => !running(pid)), 'owned workers must exit');
    origin.closeAllConnections(); await new Promise<void>(resolve => origin.close(() => resolve()));
    try { const info = await lstat(PROTOCOL.control_socket); if (info.isSocket()) await unlink(PROTOCOL.control_socket); } catch { /* already removed by native close */ }
    assert.ok(!diagnostic.includes(endpoint.password));
  });
  let owner: Socket | undefined;
  for (let i = 0; i < 150; i++) {
    try { const s = connect(PROTOCOL.control_socket); s.on('error', () => {}); await once(s, 'connect'); owner = s; break; }
    catch { if (child.exitCode !== null || child.signalCode !== null) throw Error('test-serving-start-failed'); await delay(20); }
  }
  if (!owner) throw Error('test-serving-start-failed'); links.add(owner);
  let carry = '', incarnation: unknown = null, digest: unknown = null;
  const pending = new Map<string, (value: Record<string, unknown>) => void>();
  owner.on('data', b => {
    carry += b.toString(); let newline: number;
    while ((newline = carry.indexOf('\n')) >= 0) {
      const reply = JSON.parse(carry.slice(0, newline)) as Record<string, unknown>; carry = carry.slice(newline + 1);
      validateControlResponse(reply); pending.get(reply['request_id'] as string)?.(reply); pending.delete(reply['request_id'] as string);
    }
  });
  async function call(command: string, payload: unknown = {}, extra: Record<string, unknown> = {}) {
    const id = randomBytes(16).toString('hex');
    const request = { version: 1, request_id: id, command, run_id: command === 'STATUS' ? null : manifest.run_id,
      config_digest: digest, target_incarnation: incarnation, payload, ...extra };
    const reply = await new Promise<Record<string, unknown>>((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(id); reject(Error('test-control-timeout')); }, 8000);
      pending.set(id, value => { clearTimeout(timer); resolve(value); }); owner!.write(JSON.stringify(request) + '\n');
    });
    incarnation = reply['incarnation']; digest = reply['config_digest']; return reply;
  }
  assert.equal((await call('STATUS'))['state'], 'FENCED');
  const prepare = async () => {
    const response = await call('PREPARE_RUN', { manifest, proposed_config_digest: configurationDigest(manifest), role: 'gateway', role_config: {} });
    assert.equal(response['result'], 'PREPARED'); knownWorkers = workers();
    assert.equal(knownWorkers.length, profile === 'B0' ? 1 : 2);
    assert.equal((await call('CHECK_READY'))['result'], 'READY');
  };
  const enable = async () => { assert.equal((await call('ENABLE'))['result'], 'ENABLED'); };
  function get(wire?: Uint8Array, timeoutMs = 6000) {
    return new Promise<number>((resolve, reject) => {
      const options: RequestOptions & { ALPNProtocols: string[] } = { host: '127.0.0.1', port: 443, servername: manifest.origin_name, ca: testTls.cert,
        minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'], agent: false, path: '/resource',
        headers: { Host: manifest.origin_name, ...(wire ? { Authorization: `PrivateToken token="${encodeBase64Url(wire)}"` } : {}) } };
      const req = httpsRequest(options, res => { res.resume(); res.on('error', reject); res.once('end', () => { clearTimeout(timer); resolve(res.statusCode!); }); });
      const timer = setTimeout(() => req.destroy(), timeoutMs);
      req.once('error', () => { clearTimeout(timer); reject(Error('test-serving-request-failed')); }); req.end();
    });
  }
  return { f, manifest, child, exited, owner, links, workers, prepare, enable, call, get, arrivals: () => arrivals };
}

for (const profile of ['B0', 'B1'] as const) test(`production ${profile} workers serve one shared port with real atomic replay and private control`, async t => {
  const g = await serving(t, profile), wire = await g.f.token();
  await g.prepare(); await assert.rejects(() => g.get()); await g.enable();
  assert.equal(await g.get(), 401);
  let successes = 0, exercised = false;
  for (let batch = 0; batch < 5; batch++) {
    if (batch) assert.equal((await g.call('HEARTBEAT', { seq: batch }))['result'], 'HEARTBEAT_ACK');
    const results = await Promise.allSettled(Array.from({ length: 20 }, () => g.get(wire)));
    successes += results.filter(r => r.status === 'fulfilled' && r.value === 200).length;
    const report = await g.call('REPORT'), data = report['data'] as { worker_verification_attempts: { attempts: number }[] };
    assert.equal(data.worker_verification_attempts.length, profile === 'B0' ? 1 : 2);
    if (data.worker_verification_attempts.every(w => w.attempts > 0)) { exercised = true; break; }
  }
  assert.equal(successes, 1); assert.equal(g.arrivals(), 1); assert.equal(exercised, true);
  const fenced = await g.call('FENCE', { reason: 'test-cleanup' }, { target_incarnation: null, run_id: null, config_digest: null });
  assert.equal(fenced['result'], 'FENCED'); assert.equal(g.workers().length, 0); await assert.rejects(() => g.get());
  assert.equal((await g.call('ENABLE'))['ok'], false);
});

test('owning helper loss closes all real workers; unrelated STATUS disconnect does not', async t => {
  const g = await serving(t); await g.prepare(); await g.enable();
  const other = connect(PROTOCOL.control_socket); other.on('error', () => {}); await once(other, 'connect');
  other.end(); await delay(30); assert.equal(await g.get(), 401);
  g.owner.destroy();
  for (let i = 0; i < 150 && g.workers().length; i++) await delay(20);
  assert.equal(g.workers().length, 0); await assert.rejects(() => g.get()); assert.equal(g.arrivals(), 0);
});

test('paused supervisor cannot keep worker leases alive or revive them with a late heartbeat', async t => {
  const g = await serving(t); await g.prepare(); await g.enable();
  g.child.kill('SIGSTOP'); await delay(3300); await assert.rejects(() => g.get(undefined, 250));
  g.child.kill('SIGCONT');
  const heartbeat = await g.call('HEARTBEAT', { seq: 1 }); assert.equal(heartbeat['ok'], false);
  assert.equal((await g.call('STATUS'))['state'], 'FAULTED');
  assert.equal((await g.call('FENCE', { reason: 'test-cleanup' }))['result'], 'FENCED'); assert.equal(g.workers().length, 0);
});

test('FENCE kills a stopped worker and acknowledges only after confirmed exits', async t => {
  const g = await serving(t); await g.prepare(); await g.enable(); const pid = g.workers()[0]!;
  process.kill(pid, 'SIGSTOP'); const before = process.hrtime.bigint();
  assert.equal((await g.call('FENCE', { reason: 'test-cleanup' }))['result'], 'FENCED');
  assert.ok(process.hrtime.bigint() - before >= 900000000n); assert.equal(g.workers().length, 0);
  assert.throws(() => process.kill(pid, 0)); await assert.rejects(() => g.get());
});

test('abrupt supervisor exit disconnects and terminates its real workers', async t => {
  const g = await serving(t); await g.prepare(); await g.enable(); const pids = g.workers();
  g.child.kill('SIGKILL'); await g.exited;
  for (let i = 0; i < 150 && pids.some(pid => { try { process.kill(pid, 0); return true; } catch { return false; } }); i++) await delay(20);
  // The container's PID1 may briefly retain a dead child as a zombie; no runnable process may remain.
  for (const pid of pids) {
    try { const stat = readFileSync(`/proc/${pid}/stat`, 'utf8'); assert.equal(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[0], 'Z'); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  }
  await assert.rejects(() => g.get());
});

test('private control rejects overlong, invalid UTF8/schema and duplicate-ID frames without affecting an unrelated owner', async t => {
  const g = await serving(t); await g.prepare(); await g.enable();
  const status = { version: 1, request_id: 'a'.repeat(32), command: 'STATUS', run_id: null, config_digest: null, target_incarnation: null, payload: {} };
  for (const bytes of [Buffer.alloc(65537, 120), Buffer.from([255, 10]), Buffer.from('{"bad":true}\n'),
    Buffer.from(JSON.stringify(status) + '\n' + JSON.stringify(status) + '\n')]) {
    const socket = connect(PROTOCOL.control_socket); socket.on('error', () => {}); await once(socket, 'connect');
    const closed = once(socket, 'close'); socket.resume(); socket.write(bytes); await closed;
  }
  assert.equal(await g.get(), 401); assert.equal((await g.call('STATUS'))['state'], 'ENABLED');
  assert.equal((await g.call('FENCE', { reason: 'test-cleanup' }))['result'], 'FENCED');
});

test('production control helper permits reserved FENCE alongside eight ordinary pending commands', async t => {
  const g = await serving(t); await g.prepare(); await g.enable();
  const helper = spawn(process.execPath, ['dist/control-helper.mjs'], { stdio: ['pipe', 'pipe', 'pipe'] });
  let output = '', diagnostic = ''; helper.stdout.on('data', b => { output += b.toString(); }); helper.stderr.on('data', b => { diagnostic += b.toString(); });
  const done = once(helper, 'close');
  const commands = Array.from({ length: 9 }, (_, index) => ({ version: 1, request_id: randomBytes(16).toString('hex'),
    command: index === 8 ? 'FENCE' : 'STATUS', run_id: null, config_digest: null, target_incarnation: null,
    payload: index === 8 ? { reason: 'test-cleanup' } : {} }));
  helper.stdin.end(commands.map(c => JSON.stringify(c)).join('\n') + '\n');
  const [code] = await done; assert.equal(code, 0); assert.equal(diagnostic, '');
  const replies = output.trim().split('\n').map(line => JSON.parse(line) as Record<string, unknown>);
  assert.equal(replies.length, 9); for (const reply of replies) validateControlResponse(reply);
  assert.equal(replies.filter(reply => reply['result'] === 'FENCED').length, 1); assert.equal(g.workers().length, 0);
});


// ---------------------------------------------------------------------------------------------------------------
// Public Redis bootstrap artifact (replay-bootstrap-1), against a real Redis and the production adapter.
const bootstrapManifest = async (offset = 300000) => makeManifest({ run_id: golden.manifest.run_id, run_start_ms: (await readRunStart(io)) - offset,
  token_key_spki_b64url: golden.manifest.token_key_spki_b64url, snapshot_script_sha1: REPLAY_SCRIPTS.snapshot.sha1, claim_script_sha1: REPLAY_SCRIPTS.claim.sha1 });
const snapshotOfStore = async () => ({ policy: await admin.hgetall('pp:policy'), clock: await admin.hgetall('pp:clock'), size: await admin.dbsize() });
const readyError = (reason: string) => (e: unknown) => e instanceof Error && e.message === `replay-bootstrap-${reason}`;

test('artifact: the Lua hashes are the reviewed ones and the initializer is a separate controller-only script', () => {
  assert.equal(REPLAY_SCRIPTS.snapshot.sha1, '20b8aa1866d30e41364acb05826a5617d27f1c72');
  assert.equal(REPLAY_SCRIPTS.claim.sha1, 'c4a37fc975fe7f68e73c1e0d47b4c1779a182784');
  assert.notEqual(REPLAY_INITIALIZER.sha1, REPLAY_SCRIPTS.snapshot.sha1);
  assert.ok(!GATEWAY_ACL_RULES.some((r) => /eval$|script\|load|\+@all|config|acl|flush|keys|del/i.test(r) && r !== '+evalsha'), 'the gateway ACL grants no administration');
});

test('artifact: a fresh store is initialized atomically, exactly, and passes the field-by-field readiness check', async () => {
  await admin.flushdb(); await loadReplayScripts(io);
  const manifest = await bootstrapManifest();
  await initializeStore(io, manifest);
  const want = initialStoreState(manifest);
  assert.deepEqual(await snapshotOfStore(), { policy: want.policy, clock: want.clock, size: 2 });
  assert.equal(await admin.pttl('pp:policy'), -1); assert.equal(await admin.pttl('pp:clock'), -1);
  await verifyStoreReady(io, manifest, endpoint.username);
  const store = await openRedisReplayStore(manifest, endpoint, () => {}); stores.push(store);
  m = manifest;
  assert.equal((await store.snapshot()).kind, 'snapshot', 'the production adapter accepts the artifact-initialized store');
});

test('artifact: run_start_ms comes from Redis TIME; malformed or unsafe time replies are rejected', async () => {
  const fromRedis = await readRunStart(io);
  const hostNow = Date.now();
  assert.ok(Math.abs(fromRedis - hostNow) < 60000, 'sanity: same machine');
  for (const bad of [null, [], ['1'], ['1', '2', '3'], ['01', '5'], ['-1', '5'], ['1.5', '5'], ['1e3', '5'], [1.5, 5], ['9007199254741', '5'], ['1', '1000000'], ['1', '07'], [{}, '5'], 'x', ['', '5']]) {
    assert.throws(() => parseRedisTime(bad), readyError('time-invalid'), JSON.stringify(bad));
  }
  assert.equal(parseRedisTime(['1793000000', '123456']), 1793000000123);
  assert.equal(parseRedisTime([1793000000, 5]), 1793000000000);
  await assert.rejects(readRunStart({ call: async () => { throw Error('connection lost'); } }), readyError('uncertain'));
  await assert.rejects(readRunStart({ call: async () => ['0', '0'] }), readyError('time-invalid'), 'a zero start is not a run start');
});

test('artifact: duplicate initialization and a populated store are refused before any write', async () => {
  await seed();
  const before = await snapshotOfStore();
  await assert.rejects(initializeStore(io, m), readyError('store-not-empty'));
  assert.deepEqual(await snapshotOfStore(), before, 'a second initialization changes nothing');
  await admin.flushdb(); await loadReplayScripts(io);
  await admin.set('pp:spent:' + 'b'.repeat(64), '1');
  await assert.rejects(initializeStore(io, await bootstrapManifest()), readyError('store-not-empty'));
  assert.equal(await admin.exists('pp:policy'), 0); assert.equal(await admin.exists('pp:clock'), 0);
  await admin.flushdb(); await admin.set('unrelated', 'x');
  await assert.rejects(initializeStore(io, await bootstrapManifest()), readyError('store-not-empty'), 'any key at all means the store is not fresh');
  assert.equal(await admin.exists('pp:policy'), 0);
});

test('artifact: wrong script hashes, a future start and an invalid manifest write nothing', async () => {
  await admin.flushdb(); await loadReplayScripts(io);
  const good = await bootstrapManifest();
  const wrongHash = { ...good, claim_script_sha1: '3'.repeat(40) };
  await assert.rejects(initializeStore(io, wrongHash), readyError('script-mismatch'));
  await assert.rejects(initializeStore(io, { ...good, extra: 1 }), readyError('manifest-invalid'));
  const future = await bootstrapManifest(-3_600_000);
  await assert.rejects(initializeStore(io, future), readyError('clock-unsafe'));
  assert.equal(await admin.dbsize(), 0, 'nothing was written by any refused initialization');
  // A script that is not loaded is an uncertain outcome for the caller, not silent success.
  await admin.script('FLUSH');
  await assert.rejects(initializeStore(io, good), readyError('uncertain'));
  assert.equal(await admin.dbsize(), 0);
});

test('artifact: readiness fails for every kind of wrong or tampered store state', async () => {
  const mutations: [string, string, () => Promise<unknown>][] = [
    ['policy-invalid', 'altered immutable field', () => admin.hset('pp:policy', 'run_start_ms', String(m.run_start_ms + 1))],
    ['policy-invalid', 'wrong digest stored', () => admin.hset('pp:policy', 'config_digest', '0'.repeat(64))],
    ['policy-invalid', 'extra policy field', () => admin.hset('pp:policy', 'extra', '1')],
    ['policy-invalid', 'missing policy field', () => admin.hdel('pp:policy', 'guard_ms')],
    ['policy-invalid', 'policy has a TTL', () => admin.pexpire('pp:policy', 600000)],
    ['policy-invalid', 'policy is not a hash', async () => { await admin.del('pp:policy'); await admin.set('pp:policy', 'x'); }],
    ['clock-invalid', 'clock closed', () => admin.hset('pp:clock', 'closed', '1')],
    ['clock-invalid', 'clock advanced', () => admin.hset('pp:clock', 'highest_epoch', '1')],
    ['clock-invalid', 'clock for another run', () => admin.hset('pp:clock', 'run_id', 'f'.repeat(32))],
    ['clock-invalid', 'clock missing', () => admin.del('pp:clock')],
    ['clock-invalid', 'clock has a TTL', () => admin.pexpire('pp:clock', 600000)],
    ['store-not-fresh', 'a spent key already exists', () => admin.set('pp:spent:' + 'c'.repeat(64), '1')],
    ['scripts-missing', 'scripts flushed', () => admin.script('FLUSH')],
  ];
  for (const [reason, label, mutate] of mutations) {
    await seed(); await verifyStoreReady(io, m, endpoint.username);
    await mutate();
    await assert.rejects(verifyStoreReady(io, m, endpoint.username), readyError(reason), label);
  }
  await seed();
  await assert.rejects(verifyStoreReady(io, { ...m, run_id: 'e'.repeat(32) }, endpoint.username), (e: unknown) => e instanceof Error && /^replay-bootstrap-/.test(e.message), 'a different manifest never matches');
});

test('artifact: an over-privileged or missing gateway account fails readiness; the real account cannot administer Redis', async () => {
  await seed();
  await admin.acl('SETUSER', 'gateway', '+script|load');
  await assert.rejects(verifyStoreReady(io, m, endpoint.username), readyError('acl-invalid'));
  await installGatewayAcl(io, endpoint.username, endpoint.password);
  await admin.acl('SETUSER', 'gateway', '+@all');
  await assert.rejects(verifyStoreReady(io, m, endpoint.username), readyError('acl-invalid'));
  await installGatewayAcl(io, endpoint.username, endpoint.password);
  await verifyStoreReady(io, m, endpoint.username);
  await assert.rejects(verifyStoreReady(io, m, 'nobody'), readyError('acl-invalid'));
  await assert.rejects(installGatewayAcl(io, 'default', 'p'.repeat(40)), readyError('acl-invalid'));
  await assert.rejects(installGatewayAcl(io, 'gateway', 'short'), readyError('acl-invalid'));
  await assert.rejects(installGatewayAcl(io, 'gate way', 'p'.repeat(40)), readyError('acl-invalid'));
  const gw = new Redis({ ...endpoint, protocol: 2, lazyConnect: true, enableReadyCheck: false, disableClientInfo: true, retryStrategy: () => null });
  gw.on('error', () => {}); await gw.connect();
  try {
    for (const [cmd, args] of [['EVAL', ['return 1', 0]], ['SCRIPT', ['LOAD', REPLAY_INITIALIZER.source]], ['EVALSHA', [REPLAY_INITIALIZER.sha1, 2, 'pp:policy', 'pp:clock', ...policyIdentity(m), String(m.run_start_ms)]], ['DEL', ['pp:policy']], ['KEYS', ['*']]] as const) {
      await gw.call(cmd, ...args).then(() => assert.fail(`${cmd} was allowed`), (e: Error) => assert.match(e.message, /NOPERM|ACL failure|no permissions|can't run|permission/i, `${cmd}: ${e.message}`));
    }
  } finally { gw.disconnect(false); }
  assert.equal(await admin.exists('pp:policy'), 1, 'the gateway could not touch the policy');
});

test('artifact: the password is never part of an error', async () => {
  const secret = 'S3cretPassw0rd-for-test-only-0123456789';
  try { await installGatewayAcl({ call: async () => { throw Error(`boom ${secret}`); } }, 'gateway', secret); assert.fail('should throw'); }
  catch (e) { assert.ok(e instanceof Error); assert.ok(!String(e.message).includes(secret)); assert.ok(!String((e as Error).stack).includes(secret)); }
});

test('artifact: the initializer cannot be used to reset a live run: it refuses once any key exists, including spent keys', async () => {
  await seed();
  const store = await open();
  assert.equal((await store.claim(candidate())).kind, 'claimed');
  const sizeBefore = await admin.dbsize();
  await assert.rejects(initializeStore(io, m), readyError('store-not-empty'));
  assert.equal(await admin.dbsize(), sizeBefore);
  assert.equal(await admin.get(`pp:spent:${candidate().spend_id}`), '1', 'the spent token stays spent');
});
