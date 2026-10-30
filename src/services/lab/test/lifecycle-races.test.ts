// Role lifecycle races: a FENCE must beat every in-flight key creation, bind and lease decision, and nothing late may leak out.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { connect } from 'node:net';
import { PROTOCOL, configurationDigest, hex, makeManifest, voucherDigest, encodeBase64Url } from '../../../contracts/lib/index.ts';
import { IssuerRole } from '../src/issuer/control.ts';
import { OriginRole } from '../src/origin/control.ts';
import { IssuanceService, REQUEST_TYPE } from '../src/issuer/issuance.ts';
import { VoucherStore } from '../src/issuer/vouchers.ts';
import { LabIssuer, LabIssuance, challengeFor } from '../src/protocol.ts';
import { createPki } from './helpers/pki.ts';

type Json = Record<string, any>;
const rid = () => hex(randomBytes(16));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const pki = createPki(); const leaf = pki.leaf(PROTOCOL.issuer_name);
const secrets = (p: string) => Buffer.from(p.endsWith('crt') ? leaf.cert : leaf.key);
const discovery = { version: 1, request_id: rid(), command: 'STATUS', run_id: null, config_digest: null, target_incarnation: null, payload: {} };

test('FENCE while the first issuer key is being generated: the run is latched closed, the key is never installed, FENCED waits for it', async () => {
  const role = new IssuerRole({ readSecret: secrets, listen: { host: '127.0.0.1', port: 0 }, drainMs: 3000 });
  const runId = rid();
  const create = role.handle({ version: 1, request_id: rid(), command: 'CREATE_ISSUER_KEY', run_id: runId, config_digest: null, target_incarnation: role.incarnation, payload: {} });
  await sleep(5); // key generation (RSA-2048) is now in flight
  const fence = await role.handle({ version: 1, request_id: rid(), command: 'FENCE', run_id: null, config_digest: null, target_incarnation: null, payload: { reason: 'operator-stop' } }) as Json;
  assert.equal(fence['ok'], true); assert.equal(fence['result'], 'FENCED');
  const late = await create as Json;
  assert.equal(late['ok'], false, 'the late key result is suppressed');
  assert.deepEqual(Object.keys(late['data']), []);
  const status = await role.handle(discovery) as Json;
  assert.deepEqual(status['data'], { ready: false, run_closed: true, fault: 'operator-stop' });
  const again = await role.handle({ version: 1, request_id: rid(), command: 'CREATE_ISSUER_KEY', run_id: rid(), config_digest: null, target_incarnation: role.incarnation, payload: {} }) as Json;
  assert.equal(again['ok'], false); assert.equal(again['result'], 'ILLEGAL_STATE');
});

test('a second CREATE_ISSUER_KEY while one is generating never mints a second key', async () => {
  const role = new IssuerRole({ readSecret: secrets, listen: { host: '127.0.0.1', port: 0 } });
  const mk = (run: string) => role.handle({ version: 1, request_id: rid(), command: 'CREATE_ISSUER_KEY', run_id: run, config_digest: null, target_incarnation: role.incarnation, payload: {} }) as Promise<Json>;
  const [a, b] = await Promise.all([mk(rid()), (async () => { await sleep(5); return mk(rid()); })()]);
  assert.deepEqual([a['ok'], b['ok']].sort(), [false, true]);
  await role.handle({ version: 1, request_id: rid(), command: 'FENCE', run_id: null, config_digest: null, target_incarnation: null, payload: { reason: 'test-cleanup' } });
});

const manifestFor = (issuer: LabIssuer) => makeManifest({ run_id: rid(), run_start_ms: Date.now(), token_key_spki_b64url: encodeBase64Url(issuer.publicKeySpki),
  snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40), inventory_total: 4 });

async function serviceWith(live: { value: boolean }, active = 2) {
  const issuer = await LabIssuer.generate(PROTOCOL.issuer_name);
  const manifest = manifestFor(issuer);
  const store = new VoucherStore(4); const vouchers = [randomBytes(32), randomBytes(32), randomBytes(32), randomBytes(32)];
  store.provision({ batch_id: 'a'.repeat(32), batch_index: 0, expected_total: 4, final_batch: true, items: vouchers.map(voucherDigest) }); store.lock();
  const service = new IssuanceService(issuer, store, { ...manifest.limits.issuer, active_signings: active }, () => live.value);
  service.setOpen(true);
  const body = async () => (await LabIssuance.begin(challengeFor(manifest, 0), issuer.publicKeySpki)).requestWire;
  const send = async (v: Buffer) => service.handle({ contentType: REQUEST_TYPE, voucherHeaders: [encodeBase64Url(v, false)], body: await body() });
  return { service, store, vouchers, send, issuer };
}

test('issuance checks the live lease at admission: an expired lease is 503 and the voucher is not consumed, even though the service is still "open"', async () => {
  const live = { value: true };
  const { store, vouchers, send } = await serviceWith(live);
  live.value = false; // lease lapsed, watchdog has not fired yet
  const res = await send(vouchers[0]!);
  assert.equal(res.status, 503);
  assert.equal(store.remaining, 4, 'no voucher consumed');
  live.value = true;
  assert.equal((await send(vouchers[0]!)).status, 200, 'the same voucher still works once the lease is live');
});

test('issuance re-checks the lease after queue promotion: work that waited while the lease lapsed is refused and spends nothing', async () => {
  const live = { value: true };
  const { service, store, vouchers, send, issuer } = await serviceWith(live, 1);
  // Occupy the single signing slot with a slow signer, queue a second request, then let the lease lapse before promotion.
  let finishFirst!: () => void; const slow = new Promise<void>((r) => { finishFirst = r; });
  const realSign = issuer.sign.bind(issuer);
  issuer.sign = async (w) => { await slow; return realSign(w); };
  const first = send(vouchers[0]!);
  await sleep(40);
  const queued = send(vouchers[1]!);
  await sleep(10);
  live.value = false;
  finishFirst();
  const [a, b] = await Promise.all([first, queued]);
  assert.equal(a.status, 200, 'the already-signing request settles on its own');
  assert.equal(b.status, 503, 'the queued request is refused at promotion');
  assert.equal(store.remaining, 3, 'only the voucher that actually reached signing was consumed');
  assert.equal(service.counters.issuance_successes, 1);
});

test('role level: with the lease expired and no timer firing, an issuance over the wire is refused and the role faults', async () => {
  let t = 1000;
  const role = new IssuerRole({ readSecret: secrets, clock: () => t, listen: { host: '127.0.0.1', port: 0 }, schedule: () => ({ cancel() { /* never fires */ } }) });
  const send = (command: string, payload: Json = {}, over: Json = {}) => role.handle({ version: 1, request_id: rid(), command, run_id: runId, config_digest: digest, target_incarnation: role.incarnation, payload, ...over }) as Promise<Json>;
  const runId = rid(); let digest: string | null = null;
  const key = await send('CREATE_ISSUER_KEY', {}, { config_digest: null });
  const vouchers = [randomBytes(32)];
  const m = makeManifest({ run_id: runId, run_start_ms: Date.now(), token_key_spki_b64url: key['data'].token_key_spki_b64url, snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40), inventory_total: 1 });
  await send('PREPARE_RUN', { manifest: m, proposed_config_digest: configurationDigest(m), role: 'issuer', role_config: { tls_cert_path: '/run/secrets/tls.crt', tls_key_path: '/run/secrets/tls.key' } }, { config_digest: null });
  digest = configurationDigest(m);
  await send('PROVISION_VOUCHERS', { batch_id: 'a'.repeat(32), batch_index: 0, expected_total: 1, final_batch: true, items: vouchers.map(voucherDigest) });
  await send('CHECK_READY'); assert.equal((await send('ENABLE'))['ok'], true);
  t += PROTOCOL.gateway_common.controller_lease_ms + 1;
  const { https } = await import('./helpers/https.ts');
  const res = await https(role.address!.port, pki.caPem, { method: 'POST', path: '/issue', body: new Uint8Array(259), headers: { 'Content-Type': REQUEST_TYPE, 'X-Lab-Voucher': encodeBase64Url(vouchers[0]!, false) } }).catch(() => null);
  assert.ok(res === null || res.status === 503, 'refused (503) or the listener is already gone');
  assert.equal(role.state, 'FAULTED');
  await send('FENCE', { reason: 'test-cleanup' });
});

const spki = 'MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAyxrta2qV9bHOATpM_KsluUsuZKIwNOQlCn6rQ8DfOowSmTrxKxEZCNS0cb7DHUtsmtnN2pBhKi7pA1I-beWiJNawLwnlw3TQz-Adj1KcUAp4ovZ5CPpoK1orQwyB6vGvcte155T8mKMTknaHl1fORTtSbvm_bOuZl5uEI7kPRGGiKvN6qwz1cz91l6vkTTHHMttooYHGy75gfYwOUuBlX9mZbcWE7KC-h6-814ozfRex26noKLvYHikTFxROf_ifVWGXCbCWy7nqR0zq0mTCBz_kl0DAHwDhCRBgZpg9IeX4PwhuLoI8h5zUPO9wDSo1Kpur1hLQPK0C2xNLfiJaXwIDAQAB';
const portOpen = (port: number) => new Promise<boolean>((resolve) => { const s = connect(port, '127.0.0.1'); s.once('connect', () => { s.destroy(); resolve(true); }); s.once('error', () => resolve(false)); });

test('origin: FENCE during a pending bind waits for it, nothing ever listens afterwards, and the late ENABLE cannot resurrect the run', async () => {
  let release!: () => void; const gate = new Promise<void>((r) => { release = r; });
  const origin = new OriginRole({ listen: { host: '127.0.0.1', port: 0 }, drainMs: 2000, beforeListen: () => gate });
  const m = makeManifest({ run_id: rid(), run_start_ms: Date.now(), token_key_spki_b64url: spki, snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40) });
  const digest = configurationDigest(m);
  const inc = ((await origin.handle(discovery)) as Json)['incarnation'];
  const send = (command: string, over: Json = {}, payload: Json = {}) => origin.handle({ version: 1, request_id: rid(), command, run_id: m.run_id, config_digest: digest, target_incarnation: inc, payload, ...over }) as Promise<Json>;
  await send('PREPARE_RUN', { config_digest: null }, { manifest: m, proposed_config_digest: digest, role: 'origin', role_config: {} });
  await send('CHECK_READY');
  const enable = send('ENABLE'); await sleep(20); // bind is now pending
  let fenced = false; const fence = send('FENCE', {}, { reason: 'operator-stop' }).then((r) => { fenced = true; return r; });
  await sleep(40);
  assert.equal(fenced, false, 'FENCED is not acknowledged while a bind is still pending');
  release();
  const [e, f] = await Promise.all([enable, fence]);
  assert.equal(e['ok'], false, 'the pending ENABLE fails');
  assert.equal(f['ok'], true); assert.equal(f['result'], 'FENCED'); assert.equal(origin.address, null);
  assert.equal(origin.state, 'FENCED');
});

test('origin: FENCED is returned only after the listener is fully closed and open sockets are gone', async () => {
  const origin = new OriginRole({ listen: { host: '127.0.0.1', port: 0 }, drainMs: 2000 });
  const m = makeManifest({ run_id: rid(), run_start_ms: Date.now(), token_key_spki_b64url: spki, snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40) });
  const digest = configurationDigest(m);
  const inc = ((await origin.handle(discovery)) as Json)['incarnation'];
  const send = (command: string, over: Json = {}, payload: Json = {}) => origin.handle({ version: 1, request_id: rid(), command, run_id: m.run_id, config_digest: digest, target_incarnation: inc, payload, ...over }) as Promise<Json>;
  await send('PREPARE_RUN', { config_digest: null }, { manifest: m, proposed_config_digest: digest, role: 'origin', role_config: {} });
  await send('CHECK_READY'); assert.equal((await send('ENABLE'))['ok'], true);
  const port = origin.address!.port;
  const idle = connect(port, '127.0.0.1'); await new Promise((r) => idle.once('connect', r)); // a keep-alive-style idle socket
  let closed = false; idle.once('close', () => { closed = true; });
  assert.equal((await send('FENCE', {}, { reason: 'operator-stop' }))['result'], 'FENCED');
  assert.equal(await portOpen(port), false, 'no listener once FENCED has been acknowledged');
  await sleep(20); assert.equal(closed, true, 'the open socket was torn down too');
});
