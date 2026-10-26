import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { connect, type Socket } from 'node:net';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import golden from '../../../contracts/fixtures/policy-golden.json' with { type: 'json' };
import { configurationDigest, makeManifest } from '../../../contracts/lib/index.ts';
import { WorkerLease } from '../src/worker-lease.ts';
import { FlowAdmission, type FlowPermit } from '../src/flow-admission.ts';
import { FixedOrigin, type OriginRuntime } from '../src/fixed-origin.ts';

async function fixture(t: TestContext, handler: (req: IncomingMessage, res: ServerResponse) => void,
  profile: 'B0' | 'B1' = 'B0') {
  const server = createServer(handler), serverSockets = new Set<Socket>();
  server.keepAliveTimeout = 20000;
  server.on('connection', s => { serverSockets.add(s); s.once('close', () => serverSockets.delete(s)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const port = (server.address() as { port: number }).port;
  const m = makeManifest({ run_id: golden.manifest.run_id, run_start_ms: golden.manifest.run_start_ms,
    token_key_spki_b64url: golden.manifest.token_key_spki_b64url, snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40), gateway_profile: profile });
  const ids = { worker_incarnation: '1'.repeat(32), supervisor_incarnation: '2'.repeat(32) };
  const lease = WorkerLease.prepare(m, ids, () => {}); lease.markReady();
  const issued = process.hrtime.bigint();
  lease.enable({ version: 1, run_id: m.run_id, config_digest: configurationDigest(m), ...ids,
    sequence: 0, issued_at_ns: String(issued), expires_at_ns: String(issued + 3000000000n) });
  const admission = FlowAdmission.prepare(m, lease), sockets: Socket[] = [];
  const runtime: OriginRuntime = {
    nowNs: () => process.hrtime.bigint(), schedule(ms, fn) { const timer = setTimeout(fn, ms); return () => clearTimeout(timer); },
    connect(endpoint) {
      assert.deepEqual(endpoint, { host: 'protected-origin', port: 8080 });
      const s = connect({ host: '127.0.0.1', port }); sockets.push(s); return s;
    },
  };
  const origin = FixedOrigin.prepare(m, lease, runtime);
  const permits: FlowPermit[] = [];
  async function permit() {
    const result = await admission.acquire(new AbortController().signal);
    if (result.kind !== 'admitted') throw Error('Expected flow permit'); permits.push(result.permit); return result.permit;
  }
  t.after(async () => {
    lease.fence(); await origin.close(); permits.forEach(p => p.release()); await admission.close();
    server.close(); for (const s of serverSockets) s.destroy();
  });
  return { m, lease, admission, origin, runtime, server, sockets, serverSockets, permits, permit, port };
}

test('fixed GET/run headers only, bounded byte response, and repeated permit never forwards twice', async t => {
  const seen: IncomingMessage[] = [];
  const f = await fixture(t, (req, res) => { seen.push(req); res.setHeader('Set-Cookie', 'ignored=1'); res.setHeader('Location', 'https://example.invalid'); res.end('resource'); });
  const p = await f.permit();
  const forward = f.origin.forwardAfterClaim.bind(f.origin) as (...args: unknown[]) => ReturnType<FixedOrigin['forwardAfterClaim']>;
  const result = await forward(p, { url: 'https://example.invalid', headers: { Authorization: 'must-not-forward', 'X-TokenForge-Run': 'wrong', Cookie: 'ignored=1' } });
  assert.equal(result.kind, 'response');
  if (result.kind === 'response') {
    assert.equal(Buffer.from(result.body).toString(), 'resource');
    assert.deepEqual(result.headers, { 'cache-control': 'no-store', 'content-type': 'application/octet-stream', 'content-length': '8', 'x-content-type-options': 'nosniff' });
  }
  assert.equal(seen[0]!.method, 'GET'); assert.equal(seen[0]!.url, '/resource');
  assert.deepEqual(seen[0]!.headers, { 'x-tokenforge-run': f.m.run_id, host: 'protected-origin:8080', connection: 'keep-alive' });
  assert.deepEqual(await f.origin.forwardAfterClaim(p), { kind: 'unavailable' }); assert.equal(seen.length, 1);
  p.release();
});

test('immediate sequential calls reuse a bounded socket with no hidden Agent queue', async t => {
  let arrivals = 0; const f = await fixture(t, (_req, res) => { arrivals++; res.end('ok'); });
  for (let i = 0; i < 20; i++) {
    const p = await f.permit(); assert.equal((await f.origin.forwardAfterClaim(p)).kind, 'response'); p.release();
    assert.equal(f.origin.status.queued, 0); assert.ok(f.origin.status.sockets <= 1);
  }
  assert.equal(arrivals, 20); assert.equal(f.sockets.length, 1); assert.equal(f.origin.status.idle, 1);
  assert.equal(f.sockets[0]!.timeout, 15000);
});

test('Agent-discarded keep-alive sockets settle before capacity is offered to the next request', async t => {
  const f = await fixture(t, (_req, res) => { res.setHeader('Keep-Alive', 'timeout=0'); res.end('ok'); });
  for (let i = 0; i < 5; i++) {
    const p = await f.permit(); assert.equal((await f.origin.forwardAfterClaim(p)).kind, 'response');
    assert.equal(f.origin.status.sockets, 0); assert.equal(f.origin.status.queued, 0); p.release();
  }
});

test('B1 bounds concurrent sockets and refuses overflow without queuing or starting another request', async t => {
  const responses: ServerResponse[] = []; const f = await fixture(t, (_req, res) => { responses.push(res); }, 'B1');
  const a = await f.permit(), b = await f.permit();
  const first = f.origin.forwardAfterClaim(a), second = f.origin.forwardAfterClaim(b);
  for (let i = 0; responses.length < 2 && i < 100; i++) await delay(5);
  assert.equal(responses.length, 2); assert.equal(f.origin.status.sockets, 2);
  const probe: FlowPermit = { signal: new AbortController().signal, checkActive: () => true, release() {} }; // Trusted test probe bypasses admission, not a wire credential.
  assert.deepEqual(await f.origin.forwardAfterClaim(probe), { kind: 'busy' }); assert.equal(f.origin.status.queued, 0);
  responses.forEach(r => r.end('ok')); assert.equal((await first).kind, 'response'); assert.equal((await second).kind, 'response');
  a.release(); b.release();
});

test('oversized advertised/streaming bodies and unexpected statuses never become successful resources', async t => {
  const modes = ['size', 'redirect', 'error']; let index = 0, arrivals = 0;
  const f = await fixture(t, (_req, res) => {
    arrivals++; const mode = modes[index++];
    if (mode === 'size') res.end(Buffer.alloc(16385));
    else { res.statusCode = mode === 'redirect' ? 302 : 500; res.setHeader('Location', 'https://example.invalid'); res.end('untrusted detail'); }
  });
  for (const _mode of modes) { const p = await f.permit(); assert.deepEqual(await f.origin.forwardAfterClaim(p), { kind: 'upstream-error', status: 502 }); p.release(); }
  assert.equal(arrivals, 3);
});

test('an exact 16KiB body is accepted and truncated 200 responses fail', async t => {
  let first = true;
  const f = await fixture(t, (_req, res) => {
    if (first) { first = false; res.end(Buffer.alloc(16384, 1)); }
    else { res.writeHead(200, { 'Content-Length': 100 }); res.write('short'); setImmediate(() => res.socket?.destroy()); }
  });
  const a = await f.permit(); const ok = await f.origin.forwardAfterClaim(a);
  assert.equal(ok.kind, 'response'); if (ok.kind === 'response') assert.equal(ok.body.length, 16384); a.release();
  const b = await f.permit(); assert.deepEqual(await f.origin.forwardAfterClaim(b), { kind: 'upstream-error', status: 502 }); b.release();
});

test('upgrades and excess response headers are rejected without tunnels or reflected metadata', async t => {
  let mode = 0;
  const f = await fixture(t, (_req, res) => {
    if (mode++ === 0) { res.writeHead(101, { Connection: 'Upgrade', Upgrade: 'test' }); res.end(); }
    else { for (let i = 0; i < 40; i++) res.setHeader(`X-Test-${i}`, '1'); res.end('ok'); }
  });
  for (let i = 0; i < 2; i++) { const p = await f.permit(); assert.deepEqual(await f.origin.forwardAfterClaim(p), { kind: 'upstream-error', status: 502 }); p.release(); }
});

test('absolute timeout bounds the whole streaming body, not just inactivity, with no retry', async t => {
  let arrivals = 0;
  const f = await fixture(t, (_req, res) => { arrivals++; res.writeHead(200); res.write('a'); const timer = setInterval(() => res.write('a'), 80); res.once('close', () => clearInterval(timer)); });
  const p = await f.permit();
  assert.deepEqual(await f.origin.forwardAfterClaim(p), { kind: 'upstream-error', status: 504 });
  assert.equal(arrivals, 1); assert.equal(f.origin.status.sockets, 0); assert.equal(f.admission.status.active, 1); p.release();
});

test('post-deadline response is rejected even before a delayed timeout callback executes', async t => {
  let now = 10000000000n; const f = await fixture(t, (_req, res) => { now += 2000000000n; res.end('late'); });
  f.runtime.nowNs = () => now;
  const p = await f.permit(); assert.deepEqual(await f.origin.forwardAfterClaim(p), { kind: 'upstream-error', status: 504 });
  assert.equal(f.origin.status.sockets, 0); p.release();
});

test('pool shutdown during body reception waits for actual local socket closure and does not release the flow', async t => {
  let started!: () => void; const arrived = new Promise<void>(resolve => { started = resolve; });
  const f = await fixture(t, (_req, res) => { res.write('partial'); started(); });
  const p = await f.permit(); const result = f.origin.forwardAfterClaim(p); await arrived;
  const closing = f.origin.close(); assert.equal(f.origin.close(), closing); await closing;
  assert.deepEqual(await result, { kind: 'unavailable' }); assert.equal(f.origin.status.sockets, 0);
  assert.equal(f.admission.status.active, 1); p.release();
});

test('cancellation during delayed DNS prevents a late connect callback from sending any request', async t => {
  let arrivals = 0; const f = await fixture(t, (_req, res) => { arrivals++; res.end('bad'); });
  let complete!: () => void;
  f.runtime.connect = () => connect({ host: 'delayed.test', port: f.port, lookup(_host, _options, callback) {
    complete = () => callback(null, '127.0.0.1', 4);
  } });
  const c = new AbortController(), admission = await f.admission.acquire(c.signal);
  if (admission.kind !== 'admitted') throw Error('Expected permit'); const p = admission.permit; f.permits.push(p);
  const result = f.origin.forwardAfterClaim(p); c.abort();
  assert.deepEqual(await result, { kind: 'canceled' }); assert.equal(f.origin.status.sockets, 0);
  complete(); await delay(20); assert.equal(arrivals, 0); p.release();
});

test('a stale idle timeout does not destroy a socket that has been reused for active work', async t => {
  let calls = 0; let respond!: () => void;
  const f = await fixture(t, (_req, res) => { if (calls++ === 0) res.end('first'); else respond = () => res.end('second'); });
  const a = await f.permit(); assert.equal((await f.origin.forwardAfterClaim(a)).kind, 'response'); a.release();
  const b = await f.permit(); const result = f.origin.forwardAfterClaim(b);
  for (let i = 0; !respond && i < 100; i++) await delay(5);
  assert.equal(f.sockets[0]!.timeout, 0); f.sockets[0]!.emit('timeout'); respond();
  assert.equal((await result).kind, 'response'); b.release();
});

test('lease closure and invalid configuration cannot start upstream I/O', async t => {
  let arrivals = 0; const f = await fixture(t, (_req, res) => { arrivals++; res.end(); });
  const p = await f.permit(); f.lease.fence();
  assert.deepEqual(await f.origin.forwardAfterClaim(p), { kind: 'unavailable' }); p.release();
  assert.equal(arrivals, 0);
  assert.throws(() => FixedOrigin.prepare({ ...f.m, run_id: 'f'.repeat(32) }, f.lease), /origin-configuration-invalid/);
});

test('a throwing cleanup hook faults the worker but cannot settle before its socket close is observed', async t => {
  const f = await fixture(t, (_req, res) => res.end('ok'));
  f.runtime.schedule = () => () => { throw Error('private cancellation detail'); };
  const p = await f.permit(); const result = f.origin.forwardAfterClaim(p);
  let socketClosed = false; f.sockets[0]!.once('close', () => { socketClosed = true; });
  assert.deepEqual(await result, { kind: 'unavailable' });
  assert.equal(socketClosed, true); assert.equal(f.origin.status.sockets, 0);
  assert.equal(f.origin.status.active, 0); assert.equal(f.admission.status.active, 1);
  assert.equal(f.lease.status.fault, 'unsafe-state'); p.release();
});
