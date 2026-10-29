import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { connect } from 'node:tls';
import type { Server } from 'node:https';
import {
  PROTOCOL, makeManifest, hex, sha256, encodeBase64Url, decodeBase64Url, voucherDigest,
} from '../../../contracts/lib/index.ts';
import { LabIssuer, LabIssuance, challengeFor, verifyTokenSignature } from '../src/protocol.ts';
import { VoucherStore } from '../src/issuer/vouchers.ts';
import { AdmissionGate } from '../src/issuer/admission.ts';
import { IssuanceService, REQUEST_TYPE, RESPONSE_TYPE } from '../src/issuer/issuance.ts';
import { createIssuerServer } from '../src/issuer/server.ts';
import { DIRECTORY_PATH } from '../src/issuer/directory.ts';
import { LabError } from '../src/errors.ts';
import { createPki } from './helpers/pki.ts';
import { https, listen, rawTls } from './helpers/https.ts';

const pki = createPki();
const b64 = (b: Uint8Array) => encodeBase64Url(b, false);
const newVoucher = () => randomBytes(32);
const digests = (vs: Uint8Array[]) => vs.map(voucherDigest);
const provisionAll = (store: VoucherStore, vs: Uint8Array[]) =>
  store.provision({ batch_id: '1'.repeat(32), batch_index: 0, expected_total: vs.length, final_batch: true, items: digests(vs) });

type Rig = { issuer: LabIssuer; store: VoucherStore; service: IssuanceService; server: Server; port: number; vouchers: Buffer[]; manifest: ReturnType<typeof makeManifest> };
async function rig(count = 8, signer?: { sign: (w: Uint8Array) => Promise<Uint8Array> }): Promise<Rig> {
  const issuer = await LabIssuer.generate(PROTOCOL.issuer_name);
  const manifest = makeManifest({ run_id: hex(randomBytes(16)), run_start_ms: Date.now(), token_key_spki_b64url: encodeBase64Url(issuer.publicKeySpki),
    snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40), inventory_total: count });
  const store = new VoucherStore(manifest.inventory_total);
  const vouchers = Array.from({ length: count }, newVoucher);
  provisionAll(store, vouchers);
  store.lock();
  const service = new IssuanceService(signer ? ({ publicKeySpki: issuer.publicKeySpki, sign: signer.sign } as unknown as LabIssuer) : issuer, store, manifest.limits.issuer);
  service.setOpen(true);
  const server = createIssuerServer(service, issuer.publicKeySpki, pki.leaf(PROTOCOL.issuer_name));
  return { issuer, store, service, server, port: await listen(server), vouchers, manifest };
}
const servers: Server[] = [];
const started = async (...a: Parameters<typeof rig>) => { const r = await rig(...a); servers.push(r.server); return r; };
after(() => { for (const s of servers) { s.closeAllConnections(); s.close(); } });

const post = (r: Rig, o: { body: Uint8Array; voucher?: string | string[] | null; type?: string | null; extra?: Record<string, string> }) =>
  https(r.port, pki.caPem, { method: 'POST', path: '/issue', body: o.body, headers: {
    ...(o.type === null ? {} : { 'Content-Type': o.type ?? REQUEST_TYPE }),
    ...(o.voucher === null ? {} : { 'X-Lab-Voucher': o.voucher ?? b64(r.vouchers[0]!) }), ...o.extra } });
const errorOf = (b: Buffer) => JSON.parse(b.toString()).error as string;
async function request(r: Rig, epoch = 0) {
  const issuance = await LabIssuance.begin(challengeFor(r.manifest, epoch), r.issuer.publicKeySpki);
  return issuance;
}

test('directory exposes public configuration only, with the padded RSA-PSS SPKI', async () => {
  const r = await started();
  const res = await https(r.port, pki.caPem, { path: DIRECTORY_PATH });
  assert.equal(res.status, 200);
  assert.equal(res.headers['content-type'], 'application/private-token-issuer-directory');
  assert.equal(res.headers['cache-control'], 'no-store');
  const dir = JSON.parse(res.body.toString());
  assert.deepEqual(Object.keys(dir).sort(), ['issuer-request-uri', 'token-keys']);
  assert.equal(dir['issuer-request-uri'], PROTOCOL.issuer_request_uri);
  assert.equal(dir['token-keys'].length, 1);
  assert.equal(dir['token-keys'][0]['token-type'], 2);
  const key = dir['token-keys'][0]['token-key'] as string;
  assert.match(key, /=+$|^[A-Za-z0-9_-]+$/);
  assert.equal(key, encodeBase64Url(r.issuer.publicKeySpki, true));
  assert.equal(hex(sha256(decodeBase64Url(key))), r.manifest.token_key_id);
  assert.equal((await https(r.port, pki.caPem, { method: 'POST', path: DIRECTORY_PATH, body: new Uint8Array(1), headers: { 'Content-Length': '1' } })).status, 405);
});

test('real blind issuance over TLS: 200, exact content types and sizes, finalizes, verifies publicly', async () => {
  const r = await started();
  const issuance = await request(r);
  const res = await post(r, { body: issuance.requestWire });
  assert.equal(res.status, 200);
  assert.equal(res.headers['content-type'], RESPONSE_TYPE);
  assert.equal(res.body.length, 256);
  const token = await issuance.finalize(res.body);
  assert.equal(await verifyTokenSignature(r.issuer.publicKeySpki, token), true);
  assert.deepEqual(r.service.counters, { issuance_successes: 1, issuance_failures: 0 });
});

test('a voucher authorizes exactly one signing; every refusal is the same generic 403', async () => {
  const r = await started();
  const wire = (await request(r)).requestWire;
  const first = await post(r, { body: wire, voucher: b64(r.vouchers[0]!) });
  assert.equal(first.status, 200);
  const refusals = [
    await post(r, { body: wire, voucher: b64(r.vouchers[0]!) }),          // reuse
    await post(r, { body: wire, voucher: b64(newVoucher()) }),             // unknown
    await post(r, { body: wire, voucher: null }),                          // missing
    await post(r, { body: wire, voucher: 'short' }),                       // malformed
    await post(r, { body: wire, voucher: b64(r.vouchers[1]!) + '=' }),     // padded
    await post(r, { body: wire, voucher: [b64(r.vouchers[1]!), b64(r.vouchers[2]!)] }), // duplicate header
  ];
  for (const x of refusals) { assert.equal(x.status, 403); assert.equal(errorOf(x.body), 'issuance-not-authorized'); }
  // The duplicate-header attempt consumed neither voucher.
  assert.equal(r.store.remaining, 7);
  assert.equal((await post(r, { body: (await request(r)).requestWire, voucher: b64(r.vouchers[1]!) })).status, 200);
});

test('non-canonical pad bits in a voucher are refused (43 chars carry 258 bits)', async () => {
  const r = await started();
  const v = b64(r.vouchers[0]!);
  const tweaked = v.slice(0, 42) + (v[42] === 'A' ? 'B' : 'A');
  assert.equal((await post(r, { body: (await request(r)).requestWire, voucher: tweaked })).status, 403);
  assert.equal(r.store.remaining, 8);
});

test('protocol-invalid but complete requests get 422 and consume no voucher', async () => {
  const r = await started();
  const good = (await request(r)).requestWire;
  const wrongKeyId = Uint8Array.from(good); wrongKeyId[2] = wrongKeyId[2]! ^ 1;
  const wrongType = Uint8Array.from(good); wrongType[1] = 1;
  const bad = [good.subarray(0, 258), Uint8Array.from([...good, 0]), wrongKeyId, wrongType, new Uint8Array(4096)];
  for (const body of bad) {
    const res = await post(r, { body });
    assert.equal(res.status, 422, `length ${body.length}`);
    assert.equal(errorOf(res.body), 'issuance-request-invalid');
  }
  assert.equal(r.store.remaining, 8, 'no voucher consumed');
  assert.equal((await post(r, { body: good })).status, 200);
});

test('media type is checked first; oversize and ambiguous framing are transport errors', async () => {
  const r = await started();
  const wire = (await request(r)).requestWire;
  assert.equal((await post(r, { body: wire, type: 'application/octet-stream' })).status, 415);
  assert.equal((await post(r, { body: wire, type: null })).status, 415);
  assert.equal(r.store.remaining, 8);
  const head = (extra: string) => `POST /issue HTTP/1.1\r\nHost: issuer.lab.test\r\nContent-Type: ${REQUEST_TYPE}\r\nX-Lab-Voucher: ${b64(r.vouchers[0]!)}\r\n${extra}\r\n`;
  // Declared body above the 4096-byte cap is refused without reading it.
  assert.match(await rawTls(r.port, pki.caPem, head('Content-Length: 5000\r\n')), /^HTTP\/1\.1 413 /);
  assert.match(await rawTls(r.port, pki.caPem, head('Transfer-Encoding: chunked\r\n') + '0\r\n\r\n'), /^HTTP\/1\.1 400 /);
  assert.match(await rawTls(r.port, pki.caPem, head('')), /^HTTP\/1\.1 400 /, 'missing Content-Length');
  assert.match(await rawTls(r.port, pki.caPem, head('Content-Length: 259\r\nContent-Length: 259\r\n') + 'x'.repeat(259)), /^HTTP\/1\.1 400 /, 'duplicate Content-Length');
  assert.match(await rawTls(r.port, pki.caPem, head('Content-Length: +259\r\n')), /^HTTP\/1\.1 400 /);
  assert.equal(r.store.remaining, 8, 'framing errors consume nothing');
  assert.equal((await https(r.port, pki.caPem, { path: '/issue' })).status, 405);
  assert.equal((await https(r.port, pki.caPem, { path: '/issue?x=1' })).status, 404);
  assert.equal((await https(r.port, pki.caPem, { path: '/elsewhere' })).status, 404);
});

test('header limits: more than 32 headers or more than 8192 bytes is refused', async () => {
  const r = await started();
  const many = Array.from({ length: 40 }, (_, i) => `X-A${i}: 1\r\n`).join('');
  assert.match(await rawTls(r.port, pki.caPem, `GET ${DIRECTORY_PATH} HTTP/1.1\r\nHost: issuer.lab.test\r\n${many}\r\n`), /^HTTP\/1\.1 431 /);
  assert.match(await rawTls(r.port, pki.caPem, `GET ${DIRECTORY_PATH} HTTP/1.1\r\nHost: x\r\nX-Big: ${'a'.repeat(9000)}\r\n\r\n`), /^HTTP\/1\.1 431 /);
  assert.equal((await https(r.port, pki.caPem, { path: DIRECTORY_PATH })).status, 200, 'server still healthy');
});

test('TLS 1.3 is required', async () => {
  const r = await started();
  await assert.rejects(new Promise((resolve, reject) => {
    const s = connect({ host: '127.0.0.1', port: r.port, servername: 'issuer.lab.test', ca: pki.caPem, maxVersion: 'TLSv1.2' }, () => resolve(s.getProtocol()));
    s.on('error', reject);
  }));
  await assert.rejects(https(r.port, createPki('Other CA').caPem, { path: DIRECTORY_PATH }), 'untrusted CA is not accepted by a pinned client');
});

test('closed issuer: 503 and the voucher survives; reopening works', async () => {
  const r = await started();
  const wire = (await request(r)).requestWire;
  r.service.setOpen(false);
  const res = await post(r, { body: wire });
  assert.equal(res.status, 503);
  assert.equal(r.store.remaining, 8);
  r.service.setOpen(true);
  assert.equal((await post(r, { body: wire })).status, 200);
});

test('a signing failure consumes the voucher and returns a fixed safe error', async () => {
  const r = await started(4, { sign: async () => { throw new Error('boom: secret-detail'); } });
  const res = await post(r, { body: (await request(r)).requestWire });
  assert.equal(res.status, 500);
  assert.equal(errorOf(res.body), 'issuance-failed');
  assert.doesNotMatch(res.body.toString(), /boom|secret/);
  assert.equal(r.store.remaining, 3, 'never refunded');
  assert.equal((await post(r, { body: (await request(r)).requestWire })).status, 403, 'same voucher cannot retry');
});

test('concurrent use of one voucher signs at most once', async () => {
  const r = await started();
  const wires = await Promise.all(Array.from({ length: 6 }, () => request(r)));
  const results = await Promise.all(wires.map((w) => post(r, { body: w.requestWire, voucher: b64(r.vouchers[0]!) })));
  assert.deepEqual(results.map((x) => x.status).sort(), [200, 403, 403, 403, 403, 403]);
});

test('responses carry no-store and never echo the voucher', async () => {
  const r = await started();
  const res = await post(r, { body: (await request(r)).requestWire, voucher: b64(newVoucher()) });
  assert.equal(res.headers['cache-control'], 'no-store');
  assert.equal(res.body.toString().includes('Voucher'), false);
});

test('VoucherStore: bounded, ordered, duplicate-checked, sealed provisioning with no refill', () => {
  const ds = (n: number, from = 0) => Array.from({ length: n }, (_, i) => (from + i + 1).toString(16).padStart(64, '0'));
  const batch = (over: object) => ({ batch_id: 'a'.repeat(32), batch_index: 0, expected_total: 200, final_batch: false, items: ds(128), ...over });
  const s = new VoucherStore(256);
  assert.deepEqual(s.provision(batch({})), { received_total: 128, sealed: false });
  const bad = (b: object) => assert.throws(() => s.provision(batch(b) as never), (e) => e instanceof LabError && e.result === 'BAD_MESSAGE');
  bad({ batch_index: 0 });                          // replayed batch
  bad({ batch_index: 2 });                          // skipped index
  bad({ batch_index: 1, items: ds(129, 500) });     // over 128 per frame
  bad({ batch_index: 1, items: ds(1) });            // duplicate of earlier batch
  bad({ batch_index: 1, items: [ds(1, 300)[0], ds(1, 300)[0]] }); // duplicate within a frame
  bad({ batch_index: 1, items: ['G'.repeat(64)] });  // not lowercase hex
  bad({ batch_index: 1, batch_id: 'b'.repeat(32), items: ds(1, 400) });    // different batch id
  bad({ batch_index: 1, expected_total: 150, items: ds(1, 400) });         // total changed
  bad({ batch_index: 1, final_batch: true, items: ds(10, 400) });          // seal before total reached
  bad({ batch_index: 1, items: ds(73, 400) });                             // exceeds expected total
  assert.equal(s.receivedTotal, 128, 'failed frames change nothing');
  assert.deepEqual(s.provision(batch({ batch_index: 1, final_batch: true, items: ds(72, 400) })), { received_total: 200, sealed: true });
  assert.throws(() => s.provision(batch({ batch_index: 2, items: [] })), (e) => e instanceof LabError && e.result === 'ILLEGAL_STATE');
  assert.equal(s.consume(ds(1)[0]!), false, 'nothing is spendable before lock');
  s.lock();
  assert.equal(s.consume(ds(1)[0]!), true);
  assert.equal(s.consume(ds(1)[0]!), false);
  assert.throws(() => s.provision(batch({ batch_index: 2 })), (e) => e instanceof LabError);
  assert.throws(() => new VoucherStore(16385));
  assert.throws(() => new VoucherStore(10).provision(batch({ expected_total: 11, items: ds(1) })), (e) => e instanceof LabError);
  assert.throws(() => new VoucherStore(10).lock(), (e) => e instanceof LabError && e.result === 'ILLEGAL_STATE', 'cannot lock unsealed');
});

test('AdmissionGate: bounded active/queue, FIFO, expiry and cancel', async () => {
  const g = new AdmissionGate(2, 2, 40);
  const a = (await g.acquire())!, b = (await g.acquire())!;
  assert.notEqual(a, null); assert.notEqual(b, null);
  const order: number[] = [];
  const c = g.acquire().then((r) => { order.push(3); return r; });
  const d = g.acquire().then((r) => { order.push(4); return r; });
  assert.equal(await g.acquire(), null, 'queue full is immediate');
  a(); a(); // idempotent release frees exactly one permit
  const rc = await c; assert.ok(rc);
  assert.equal(g.running, 2);
  assert.equal(await d, null, 'queued request expires after the wait');
  assert.deepEqual(order, [3, 4]);
  const e = g.acquire(); g.cancelQueued(); assert.equal(await e, null);
  b(); rc!();
  assert.equal(g.running, 0);
});
