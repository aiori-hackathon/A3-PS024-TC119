import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { createServer } from 'node:https';
import {
  PROTOCOL, challengeBytes, encodeBase64Url, hex, sha256, makeManifest, redemptionContext,
} from '../../../contracts/lib/index.ts';
import { LabClient, LabClientError } from '../src/client/client.ts';
import { ClientVouchers } from '../src/client/vouchers.ts';
import { TokenInventory } from '../src/client/inventory.ts';
import { parseChallenge } from '../src/client/challenge.ts';
import { createPki } from './helpers/pki.ts';
import { listen } from './helpers/https.ts';
import { startRig } from './helpers/rig.ts';
import { startProxy } from './helpers/stubs.ts';

const rejectsWith = (p: Promise<unknown>, code: string, status?: number) =>
  assert.rejects(p, (e) => e instanceof LabClientError && e.code === code && (status === undefined || e.status === status));

test('end to end through CONNECT: directory, challenge, blind issuance, redemption, replay refused', async () => {
  const rig = await startRig(3);
  try {
    const c = rig.client();
    await c.checkDirectory();
    const parsed = await c.fetchChallenge();
    assert.equal(parsed.epoch, 0);
    await c.obtainToken(parsed);
    assert.equal(c.tokens.size, 1);
    const ok = await c.redeem(parsed.epoch);
    assert.equal(ok.status, 200);
    assert.equal(c.tokens.size, 0, 'token removed when handed out');
    await rejectsWith(c.redeem(parsed.epoch), 'no-token');
    // Replay at the (stub) gateway: the same bytes are refused with a fresh challenge.
    const used = [...rig.gateway.spent][0]!;
    const replay = await c.redeemWire(Uint8Array.from(Buffer.from(used, 'base64url')));
    assert.equal(replay.status, 401);
    assert.equal(replay.wwwAuthenticate.length, 1);
    assert.deepEqual([...new Set(rig.proxy.connects)].sort(), ['issuer.lab.test:443', 'origin.lab.test:443']);
  } finally { await rig.stop(); }
});

test('every voucher is used once: sequential issuances consume distinct vouchers and the inventory empties', async () => {
  const rig = await startRig(3);
  try {
    const v = rig.clientVouchers();
    const c = rig.client({ vouchers: v });
    const parsed = await c.fetchChallenge();
    for (let i = 0; i < 3; i++) await c.obtainToken(parsed);
    assert.equal(v.remaining, 0);
    await rejectsWith(c.obtainToken(parsed), 'no-voucher');
    assert.equal(c.tokens.size, 3);
    // Three distinct tokens, all redeemable once.
    for (let i = 0; i < 3; i++) assert.equal((await c.redeem(0)).status, 200);
    assert.equal(rig.gateway.spent.size, 3);
  } finally { await rig.stop(); }
});

test('an issuer refusal is reported by status only; the voucher is spent and not retried', async () => {
  const rig = await startRig(2);
  try {
    const first = rig.client(); const second = rig.client(); // both hold the same two plaintext vouchers
    const parsed = await first.fetchChallenge();
    await first.obtainToken(parsed);
    await second.fetchChallenge();
    await rejectsWith(second.obtainToken(parsed), 'issuance-refused', 403); // first voucher already used server-side
    assert.equal(second.tokens.size, 0);
    await second.obtainToken(parsed); // its next voucher is a different, still-valid one
    assert.equal(second.tokens.size, 1);
  } finally { await rig.stop(); }
});

test('five clients share one proxy, each with its own inventory, and obtain two tokens each', async () => {
  const rig = await startRig(10);
  try {
    const pool = rig.vouchers.map((b) => encodeBase64Url(b, false));
    const clients = pool.length && Array.from({ length: 5 }, (_, i) => {
      const v = new ClientVouchers(2);
      v.provision({ batch_id: 'f'.repeat(32), batch_index: 0, expected_total: 2, final_batch: true, items: pool.slice(i * 2, i * 2 + 2) });
      v.lock();
      return rig.client({ vouchers: v });
    });
    await Promise.all((clients as LabClient[]).map(async (c) => { const p = await c.fetchChallenge(); await c.obtainToken(p); await c.obtainToken(p); }));
    for (const c of clients as LabClient[]) assert.equal(c.tokens.size, 2);
    const results = await Promise.all((clients as LabClient[]).flatMap((c) => [c.redeem(0), c.redeem(0)]));
    assert.ok(results.every((r) => r.status === 200));
    assert.equal(rig.gateway.spent.size, 10);
  } finally { await rig.stop(); }
});

test('socket bound: at most 2 concurrent sockets to the issuer per client process', async () => {
  const rig = await startRig(6);
  try {
    const c = rig.client();
    const parsed = await c.fetchChallenge();
    await Promise.all(Array.from({ length: 6 }, () => c.obtainToken(parsed)));
    assert.equal(c.tokens.size, 6);
    assert.ok(rig.proxy.peak() <= 3, `peak concurrent tunnels ${rig.proxy.peak()}`); // 2 issuer + the gateway tunnel
    assert.ok(rig.proxy.connects.filter((x) => x.startsWith('issuer')).length <= 2, 'issuer tunnels are reused, not reopened');
  } finally { await rig.stop(); }
});

test('trust: wrong CA, wrong server name, refused CONNECT and CONNECT with extra bytes all fail closed', async () => {
  const rig = await startRig(6);
  try {
    await rejectsWith(rig.client({ caPem: createPki('Other CA').caPem }).fetchChallenge(), 'transport');
    // A server for origin.lab.test presenting a certificate for another name.
    const imposter = createServer({ ...rig.pki.leaf('evil.lab.test'), minVersion: 'TLSv1.3' }, (_q, r) => r.end('x'));
    const port = await listen(imposter);
    const proxy = await startProxy({ 'origin.lab.test:443': port, 'issuer.lab.test:443': port });
    await rejectsWith(rig.client({ proxy: { host: '127.0.0.1', port: proxy.port } }).fetchChallenge(), 'transport');
    imposter.close(); proxy.server.close();
    rig.proxy.setMode('refuse');
    await rejectsWith(rig.client().fetchChallenge(), 'transport');
    rig.proxy.setMode('extra');
    await rejectsWith(rig.client().fetchChallenge(), 'transport');
    rig.proxy.setMode('ok');
    assert.equal((await rig.client().fetchChallenge()).epoch, 0);
  } finally { await rig.stop(); }
});

test('only the two pinned lab hostnames on 443 can be dialled, whatever the manifest or caller asks', async () => {
  const rig = await startRig(2);
  try {
    const before = rig.proxy.connects.length;
    const c = rig.client({ manifest: { ...rig.manifest, origin_name: 'origin.lab.test' } });
    // Reaching any other authority must fail before the proxy sees a CONNECT.
    const { TunnelAgent } = await import('../src/client/tunnel.ts');
    const agent = new TunnelAgent({ proxy: { host: '127.0.0.1', port: rig.proxy.port }, caPem: rig.pki.caPem, allowedHosts: ['issuer.lab.test', 'origin.lab.test'], maxSockets: 2 });
    for (const [host, port] of [['example.com', 443], ['issuer.lab.test', 8443], ['127.0.0.1', 443], ['issuer.lab.test.evil', 443]] as const) {
      await assert.rejects(new Promise((resolve, reject) => agent.createConnection({ host, port, servername: host }, (e, s) => (e ? reject(e) : resolve(s)))), /destination-not-allowed/);
    }
    assert.equal(rig.proxy.connects.length, before);
    agent.destroy(); void c;
  } finally { await rig.stop(); }
});

test('challenge handling: exactly one strict PrivateToken challenge for the pinned key, run and epoch', async () => {
  const rig = await startRig(2);
  try {
    const m = rig.manifest;
    const good = `PrivateToken challenge="${encodeBase64Url(challengeBytes(m, 0))}", token-key="${m.token_key_spki_b64url}"`;
    assert.equal(parseChallenge([good], m, [0]).epoch, 0);
    const other = makeManifest({ run_id: 'ab'.repeat(16), run_start_ms: m.run_start_ms, token_key_spki_b64url: m.token_key_spki_b64url,
      snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40) });
    const wrongKey = (await startRig(1));
    const bad: [string, string[]][] = [
      ['missing header', []],
      ['duplicate headers', [good, good]],
      ['wrong scheme', [good.replace('PrivateToken', 'Bearer')]],
      ['unquoted values', [good.replace(/"/g, '')]],
      ['extra parameter', [good + ', max-age=1']],
      ['swapped order', [`PrivateToken token-key="${m.token_key_spki_b64url}", challenge="${encodeBase64Url(challengeBytes(m, 0))}"`]],
      ['duplicate challenge field', [good.replace(', token-key', `", challenge="AAAA", token-key`)]],
      ['different run (context mismatch)', [`PrivateToken challenge="${encodeBase64Url(challengeBytes(other, 0))}", token-key="${m.token_key_spki_b64url}"`]],
      ['unaccepted epoch', [`PrivateToken challenge="${encodeBase64Url(challengeBytes(m, 5))}", token-key="${m.token_key_spki_b64url}"`]],
      ['advertised key differs from pinned', [`PrivateToken challenge="${encodeBase64Url(challengeBytes(m, 0))}", token-key="${wrongKey.manifest.token_key_spki_b64url}"`]],
      ['truncated challenge', [`PrivateToken challenge="${encodeBase64Url(challengeBytes(m, 0).subarray(0, 60))}", token-key="${m.token_key_spki_b64url}"`]],
      ['trailing byte in challenge', [`PrivateToken challenge="${encodeBase64Url(Uint8Array.from([...challengeBytes(m, 0), 0]))}", token-key="${m.token_key_spki_b64url}"`]],
    ];
    await wrongKey.stop();
    for (const [why, values] of bad) assert.throws(() => parseChallenge(values, m, [0]), Error, why);
    // Wire-level: a gateway returning a hostile challenge is refused, and no voucher is spent.
    const v = rig.clientVouchers(); const c = rig.client({ vouchers: v });
    rig.gateway.header.override = bad[3]![1][0]!; // unquoted values
    await rejectsWith(c.fetchChallenge(), 'challenge-unavailable', undefined);
    rig.gateway.header.override = null;
    assert.equal(v.remaining, 2);
    assert.equal(hex(redemptionContext(m, 0)).length, 64);
  } finally { await rig.stop(); }
});

test('transport hardening: redirects, oversize replies and stalls are refused', async () => {
  const rig = await startRig(2);
  try {
    const hostile = createServer({ ...rig.pki.leaf(PROTOCOL.origin_name), minVersion: 'TLSv1.3' }, (req, res) => {
      if (req.url === '/resource' && req.headers['x-mode'] === undefined) { res.writeHead(302, { Location: 'https://example.com/' }); res.end(); }
    });
    const port = await listen(hostile);
    const proxy = await startProxy({ 'origin.lab.test:443': port, 'issuer.lab.test:443': rig.role.address!.port });
    const c = rig.client({ proxy: { host: '127.0.0.1', port: proxy.port }, requestTimeoutMs: 400 });
    await rejectsWith(c.fetchChallenge(), 'redirect-refused');
    hostile.removeAllListeners('request');
    hostile.on('request', (_q, r) => { r.writeHead(401, { 'Content-Length': '40000' }); r.write(Buffer.alloc(30000)); });
    await rejectsWith(c.fetchChallenge(), 'response-too-large');
    hostile.removeAllListeners('request');
    hostile.on('request', () => undefined); // never answers
    await rejectsWith(c.fetchChallenge(), 'transport');
    hostile.closeAllConnections(); hostile.close(); proxy.server.close();
  } finally { await rig.stop(); }
});

test('a forged issuance response never becomes an inventory token, and the voucher is still spent', async () => {
  const rig = await startRig(2);
  try {
    // An impostor issuer behind the real hostname: right TLS, wrong key material.
    const fake = createServer({ ...rig.pki.leaf(PROTOCOL.issuer_name), minVersion: 'TLSv1.3' }, (req, res) => {
      req.resume();
      req.on('end', () => { res.writeHead(200, { 'Content-Type': 'application/private-token-response', 'Content-Length': '256' }); res.end(Buffer.alloc(256, 7)); });
    });
    const port = await listen(fake);
    const proxy = await startProxy({ 'origin.lab.test:443': rig.gateway.port, 'issuer.lab.test:443': port });
    const v = rig.clientVouchers();
    const c = rig.client({ proxy: { host: '127.0.0.1', port: proxy.port }, vouchers: v });
    const parsed = await c.fetchChallenge();
    await rejectsWith(c.obtainToken(parsed), 'issuance-invalid');
    assert.equal(c.tokens.size, 0);
    assert.equal(v.remaining, 1);
    fake.closeAllConnections(); fake.close(); proxy.server.close();
  } finally { await rig.stop(); }
});

test('directory mismatch is detected rather than adopted', async () => {
  const rig = await startRig(2);
  try {
    const other = await startRig(1);
    const c = rig.client({ manifest: other.manifest });
    await rejectsWith(c.checkDirectory(), 'directory-mismatch');
    await other.stop();
  } finally { await rig.stop(); }
});

test('secrets do not leak through inspection, JSON, or the inventory API', () => {
  const v = new ClientVouchers(2);
  const secret = encodeBase64Url(Uint8Array.from({ length: 32 }, (_, i) => i + 1), false);
  v.provision({ batch_id: 'a'.repeat(32), batch_index: 0, expected_total: 1, final_batch: true, items: [secret] });
  v.lock();
  assert.doesNotMatch(inspect(v, { depth: 5, showHidden: true }) + JSON.stringify(v), new RegExp(secret));
  const inv = new TokenInventory(2);
  inv.add(0, Uint8Array.from({ length: 354 }, (_, i) => i % 251));
  assert.equal(JSON.stringify(inv), '"[TokenInventory]"');
  assert.doesNotMatch(inspect(inv, { showHidden: true }), /\d{3}, \d{3}/);
  assert.equal(Object.keys(inv).length, 0);
  inv.add(0, new Uint8Array(354));
  assert.throws(() => inv.add(0, new Uint8Array(354)), (e: Error) => e.message === 'ILLEGAL_STATE');
  assert.equal(inv.take(1), undefined);
  assert.ok(inv.take(0));
  void hex; void sha256;
});

test('ClientVouchers: bounded, sealed, canonical, no refill, nothing spendable before lock', () => {
  const item = (n: number) => encodeBase64Url(Uint8Array.from({ length: 32 }, () => n), false);
  const base = { batch_id: 'a'.repeat(32), batch_index: 0, expected_total: 3, final_batch: false };
  const v = new ClientVouchers(3);
  assert.equal(v.take(), undefined);
  assert.throws(() => v.provision({ ...base, items: [item(1)] .concat('A'.repeat(42) + 'B') }));          // non-canonical pad bits
  assert.throws(() => v.provision({ ...base, items: [item(1), item(1)] }));                               // duplicate in frame
  assert.throws(() => v.provision({ ...base, items: [item(1) + '='] }));                                  // padded
  assert.deepEqual(v.provision({ ...base, items: [item(1), item(2)] }), { received_total: 2, sealed: false });
  assert.deepEqual(v.provision({ ...base, batch_index: 1, final_batch: true, items: [item(3)] }), { received_total: 3, sealed: true });
  assert.equal(v.take(), undefined, 'not spendable before ENABLE');
  assert.throws(() => v.provision({ ...base, batch_index: 2, items: [item(4)] }));
  v.lock();
  assert.deepEqual([...v.take()!.subarray(0, 1)], [1]);
  assert.equal(v.remaining, 2);
  assert.throws(() => new ClientVouchers(2).lock(), (e: Error) => e.message === 'ILLEGAL_STATE');
});
