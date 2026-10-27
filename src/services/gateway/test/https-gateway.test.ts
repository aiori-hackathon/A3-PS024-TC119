import test, { before, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { connect as tlsConnect, TLSSocket, type ConnectionOptions } from 'node:tls';
import { connect as tcpConnect, type Socket } from 'node:net';
import { once } from 'node:events';
import { setImmediate as turn, setTimeout as delay } from 'node:timers/promises';
import golden from '../../../contracts/fixtures/policy-golden.json' with { type: 'json' };
import { configurationDigest, validateManifest } from '../../../contracts/lib/index.ts';
import { WorkerLease, type LeaseRuntime } from '../src/worker-lease.ts';
import { HttpsGateway, type GatewayTls } from '../src/https-gateway.ts';
import { GatewayResponses, copyRawHeaders } from '../src/http-auth.ts';
import type { RequestView, ResponseSink } from '../src/request-coordinator.ts';
import { createTestTls } from '../scripts/create-test-tls.ts';

let material: GatewayTls;
before(async () => { material = await createTestTls(); });
const request = 'GET /resource HTTP/1.1\r\nHost: origin.lab.test\r\n\r\n';
async function fixture(t: TestContext, handle?: (view: RequestView, sink: ResponseSink) => Promise<void>,
  runtime?: LeaseRuntime, listen = true, onClose?: () => void) {
  const m = validateManifest(structuredClone(golden.manifest)), digest = configurationDigest(m);
  const ids = { worker_incarnation: '1'.repeat(32), supervisor_incarnation: '2'.repeat(32) };
  const lease = WorkerLease.prepare(m, ids, () => onClose?.()); lease.markReady();
  const formatter = GatewayResponses.prepare(m);
  const snapshot = ['SNAPSHOT', m.run_id, m.token_key_id, digest, m.run_start_ms + 1, 0, m.run_start_ms, m.run_start_ms + m.epoch_ms];
  let handled = 0, closes = 0, seq = 0;
  const coordinator = { binding: { run_id: m.run_id, config_digest: digest },
    async handle(view: RequestView, sink: ResponseSink) {
      handled++;
      if (handle) await handle(view, sink);
      else await sink(formatter.rejection(view.hasBody || !copyRawHeaders(view.rawHeaders) ? 'request-malformed' : 'token-required', snapshot), view.signal);
    }, async close() { closes++; } };
  const server = HttpsGateway.prepare(m, lease, coordinator, material, runtime);
  const stamp = process.hrtime.bigint(); lease.enable({ version: 1, run_id: m.run_id, config_digest: digest, ...ids,
    sequence: 0, issued_at_ns: String(stamp), expires_at_ns: String(stamp + 3000000000n) });
  const heartbeat = setInterval(() => { if (lease.status.state === 'ENABLED') {
    const now = process.hrtime.bigint(); lease.heartbeat({ version: 1, run_id: m.run_id, config_digest: digest, ...ids,
      sequence: ++seq, issued_at_ns: String(now), expires_at_ns: String(now + 3000000000n) });
  } }, 1000);
  let port = 0; if (listen) port = (await server.listen('127.0.0.1', 0)).port;
  const clients = new Set<Socket>(), cleanup = { allowFailure: false };
  t.after(async () => {
    clearInterval(heartbeat); for (const client of clients) client.destroy();
    try { await server.close(); } catch (error) { if (!cleanup.allowFailure) throw error; }
  });
  async function tls(options: ConnectionOptions = {}): Promise<TLSSocket> {
    const socket = tlsConnect({ host: '127.0.0.1', port, servername: m.origin_name, ca: material.cert,
      minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'], ...options });
    clients.add(socket); socket.on('error', () => {});
    await once(socket, 'secureConnect'); socket.resume(); return socket;
  }
  async function exchange(bytes: string) {
    const socket = await tls(); const chunks: Buffer[] = [];
    socket.on('data', chunk => chunks.push(chunk)); const closed = once(socket, 'close'); socket.write(bytes); await closed;
    return Buffer.concat(chunks).toString();
  }
  return { m, lease, server, coordinator, tls, exchange, clients, cleanup, port, handled: () => handled, closes: () => closes };
}

test('validated CA/SNI/TLS1.3 HTTP1.1 returns a challenge and closes the connection', async t => {
  const f = await fixture(t), socket = await f.tls();
  assert.equal(socket.authorized, true); assert.equal(socket.getProtocol(), 'TLSv1.3'); assert.equal(socket.alpnProtocol, 'http/1.1');
  const parts: Buffer[] = []; socket.on('data', data => parts.push(data)); const closed = once(socket, 'close'); socket.write(request); await closed;
  const reply = Buffer.concat(parts).toString(); assert.match(reply, /^HTTP\/1.1 401/);
  assert.match(reply, /www-authenticate: PrivateToken challenge=/i); assert.match(reply, /connection: close/i); assert.match(reply, /cache-control: no-store/i);
  assert.equal(f.handled(), 1); await turn(); assert.equal(f.server.status.sockets, 0);
});

test('TLS1.2, wrong/absent SNI, h2-only ALPN and untrusted certificates do not reach HTTP', async t => {
  const f = await fixture(t);
  for (const options of [
    { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' }, { servername: 'other.lab.test' }, { servername: '' },
    { ALPNProtocols: ['h2'] }, { ca: [] },
  ] as ConnectionOptions[]) await assert.rejects(() => f.tls(options));
  assert.equal(f.handled(), 0);
});

test('missing ALPN is explicitly accepted as HTTP1.1; HTTP1.0 is rejected', async t => {
  const f = await fixture(t); const socket = await f.tls({ ALPNProtocols: [] });
  const chunks: Buffer[] = []; socket.on('data', b => chunks.push(b)); const closed = once(socket, 'close'); socket.write(request); await closed;
  assert.match(Buffer.concat(chunks).toString(), /^HTTP\/1.1 401/);
  assert.equal(await f.exchange('GET /resource HTTP/1.0\r\nHost: origin.lab.test\r\n\r\n'), '');
  assert.equal(f.handled(), 1);
});

test('native header bytes and full raw field-count limits cannot be bypassed by truncation', async t => {
  const f = await fixture(t);
  const overflow = await f.exchange(`GET /resource HTTP/1.1\r\nHost: origin.lab.test\r\nX-Pad: ${'x'.repeat(9000)}\r\n\r\n`);
  assert.equal(overflow, ''); assert.equal(f.handled(), 0);
  const many = await f.exchange(`GET /resource HTTP/1.1\r\nHost: origin.lab.test\r\n${Array.from({ length: 33 }, (_, i) => `X-${i}: 1\r\n`).join('')}\r\n`);
  assert.match(many, /^HTTP\/1.1 400/);
});

test('ambiguous framing and special protocol events close without automatic100/tunnel responses', async t => {
  const f = await fixture(t);
  for (const suffix of [
    'Content-Length: 0\r\nContent-Length: 0', 'Transfer-Encoding: chunked\r\nContent-Length: 0',
    'Expect: 100-continue', 'Expect: something', 'Connection: Upgrade\r\nUpgrade: test',
  ]) {
    const out = await f.exchange(`GET /resource HTTP/1.1\r\nHost: origin.lab.test\r\n${suffix}\r\n\r\n`);
    assert.equal(out, '');
  }
  assert.equal(await f.exchange('CONNECT origin.lab.test:443 HTTP/1.1\r\nHost: origin.lab.test\r\n\r\n'), '');
  assert.equal(f.handled(), 0);
});

test('declared GET bodies are rejected before body arrival and received body bytes abort the connection', async t => {
  const f = await fixture(t);
  assert.match(await f.exchange('GET /resource HTTP/1.1\r\nHost: origin.lab.test\r\nContent-Length: 1\r\n\r\n'), /^HTTP\/1.1 400/);
  const out = await f.exchange('GET /resource HTTP/1.1\r\nHost: origin.lab.test\r\nContent-Length: 1\r\n\r\nx');
  assert.doesNotMatch(out, /^HTTP\/1.1 200/);
});

test('coalesced and fragmented pipelining never dispatch a second request', async t => {
  const f = await fixture(t); await f.exchange(request + request); assert.ok(f.handled() <= 1);
  const before = f.handled(); const socket = await f.tls(); const closed = once(socket, 'close');
  socket.write(request + 'GET /reso'); await closed;
  assert.equal(socket.destroyed, true); assert.ok(f.handled() <= before + 1);
});

test('raw pre-TLS sockets are capped at64 and stalled handshakes expire at the absolute header deadline', async t => {
  const f = await fixture(t); const peers: Socket[] = [];
  for (let i = 0; i < 65; i++) { const peer = tcpConnect({ host: '127.0.0.1', port: f.port }); peer.on('error', () => {}); peers.push(peer); f.clients.add(peer); }
  await Promise.all(peers.map(p => once(p, 'connect'))); await turn();
  assert.ok(f.server.status.sockets <= 64); assert.equal(f.handled(), 0);
  await delay(2200); assert.equal(f.server.status.sockets, 0);
});

test('slow fragmented HTTP headers do not refresh the TCP-accept deadline', async t => {
  const f = await fixture(t), socket = await f.tls(); const closed = once(socket, 'close'); socket.write('GET /resource HTTP/1.1\r\nHost: ');
  const timer = setInterval(() => { if (!socket.destroyed) socket.write('a'); }, 100);
  try { await closed; } finally { clearInterval(timer); }
  for (let i = 0; f.server.status.sockets && i < 50; i++) await delay(5);
  assert.equal(f.handled(), 0); assert.equal(f.server.status.sockets, 0);
});

test('a delayed timer cannot admit already-expired complete headers', async t => {
  let now = 10000000000n;
  const runtime: LeaseRuntime = { nowNs: () => now, schedule(ms, fn) { const timer = setTimeout(fn, ms); return () => clearTimeout(timer); } };
  const f = await fixture(t, undefined, runtime), socket = await f.tls(); const closed = once(socket, 'close');
  now += 2000000000n; socket.write(request); await closed; assert.equal(f.handled(), 0);
});

test('the full request deadline closes a stalled handler even while the worker lease is renewed', async t => {
  const f = await fixture(t, async view => { await new Promise<void>(resolve => view.signal.addEventListener('abort', () => resolve(), { once: true })); });
  const socket = await f.tls(), closed = once(socket, 'close'); socket.write(request); await closed;
  await turn(); assert.equal(f.handled(), 1); assert.equal(f.server.status.handlers, 0); assert.equal(f.lease.status.state, 'ENABLED');
});

test('empty502/504 mapping adds no new public error labels', async t => {
  let count = 0;
  const f = await fixture(t, async (view, sink) => { await sink({ kind: 'upstream-error', status: count++ === 0 ? 502 : 504 }, view.signal); });
  for (const status of [502, 504]) {
    const out = await f.exchange(request); assert.match(out, new RegExp(`^HTTP/1.1 ${status}`));
    assert.match(out, /content-length: 0/i); assert.equal(out.split('\r\n\r\n')[1], '');
  }
});

test('shutdown waits for handler cleanup and publishes a single promise before reentrant callbacks', async t => {
  let release!: () => void, started!: () => void, ref: HttpsGateway | undefined, nested: Promise<void> | undefined;
  const entered = new Promise<void>(resolve => { started = resolve; });
  const f = await fixture(t, async () => { started(); await new Promise<void>(resolve => { release = resolve; }); }, undefined, true, () => { nested = ref!.close(); });
  ref = f.server; const socket = await f.tls(); socket.write(request); await entered;
  let drained = false; const closing = f.server.close(); closing.then(() => { drained = true; });
  try { await turn(); assert.equal(nested, closing); assert.equal(drained, false); assert.equal(f.server.status.handlers, 1); }
  finally { release(); await closing; }
  assert.equal(f.closes(), 1); assert.equal(f.server.status.sockets, 0);
});

test('closing during an unresolved listen cannot leave a late listener open', async t => {
  const f = await fixture(t, undefined, undefined, false);
  const pending = f.server.listen('127.0.0.1', 0); const rejected = assert.rejects(pending, /https-listen-failed/);
  await Promise.all([f.server.close(), rejected]); assert.equal(f.server.status.listening, false); assert.equal(f.server.status.closed, true);
});

test('cancellation during a controlled pending TLS write waits for local socket closure without a late response', async t => {
  const f = await fixture(t); let entered!: () => void, held: TLSSocket | undefined, closed = false;
  const pending = new Promise<void>(resolve => { entered = resolve; });
  const completions: (() => void)[] = [];
  const prototype = TLSSocket.prototype as unknown as Record<string, (...args: unknown[]) => unknown>;
  const saved = ['_write', '_writev'].map(name => ({ name, own: Object.getOwnPropertyDescriptor(prototype, name), original: prototype[name]! }));
  for (const { name, original } of saved) prototype[name] = function(this: TLSSocket, ...args: unknown[]) {
    if (this.localPort !== f.port) return Reflect.apply(original, this, args);
    held = this; this.once('close', () => { closed = true; });
    completions.push(() => (args.at(-1) as () => void)()); entered();
  };
  try {
    const peer = await f.tls(); const received: Buffer[] = []; peer.on('data', b => received.push(b)); peer.write(request);
    await pending; assert.equal(f.server.status.handlers, 1); assert.ok(held);
    await f.server.close();
    assert.equal(closed, true); assert.equal(f.server.status.handlers, 0); assert.equal(f.server.status.sockets, 0);
    completions.splice(0).forEach(complete => complete()); await turn();
    assert.equal(Buffer.concat(received).length, 0);
  } finally {
    for (const { name, own } of saved) { if (own) Object.defineProperty(prototype, name, own); else delete prototype[name]; }
    completions.forEach(complete => complete());
  }
});

test('a delayed native write completion cannot succeed beyond the absolute request deadline', async t => {
  let now = 10000000000n, accepted = false, rejected = false;
  const runtime: LeaseRuntime = { nowNs: () => now, schedule(ms, fn) { const timer = setTimeout(fn, ms); return () => clearTimeout(timer); } };
  const f = await fixture(t, async (view, sink) => {
    try { await sink({ status: 400, headers: { 'content-length': '0', 'cache-control': 'no-store' }, body: '' }, view.signal); accepted = true; }
    catch { rejected = true; }
  }, runtime);
  const prototype = TLSSocket.prototype as unknown as Record<string, (...args: unknown[]) => unknown>;
  const saved = ['_write', '_writev'].map(name => ({ name, own: Object.getOwnPropertyDescriptor(prototype, name), original: prototype[name]! }));
  for (const { name, original } of saved) prototype[name] = function(this: TLSSocket, ...args: unknown[]) {
    if (this.localPort === f.port) {
      const callback = args.at(-1) as (...values: unknown[]) => void;
      args[args.length - 1] = (...values: unknown[]) => { now += 5000000000n; callback(...values); };
    }
    return Reflect.apply(original, this, args);
  };
  try {
    await f.exchange(request);
    for (let i = 0; f.server.status.handlers && i < 50; i++) await delay(5);
    assert.equal(accepted, false); assert.equal(rejected, true);
  } finally { for (const { name, own } of saved) { if (own) Object.defineProperty(prototype, name, own); else delete prototype[name]; } }
});

test('a synchronous coordinator cleanup failure rejects the cached drain after independent cleanup', async t => {
  const f = await fixture(t); f.cleanup.allowFailure = true;
  f.coordinator.close = () => { throw Error('private cleanup detail'); };
  const closing = f.server.close(); assert.equal(f.server.close(), closing);
  await assert.rejects(closing, /https-close-failed/); assert.equal(f.server.status.sockets, 0); assert.equal(f.server.status.listening, false);
});
