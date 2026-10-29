import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  PROTOCOL, makeManifest, configurationDigest, encodeBase64Url, voucherDigest, hex, validateControlResponse, type Manifest,
} from '../../../contracts/lib/index.ts';
import { IssuerRole } from '../src/issuer/control.ts';
import { LabIssuance, challengeFor, verifyTokenSignature } from '../src/protocol.ts';
import { REQUEST_TYPE } from '../src/issuer/issuance.ts';
import { createPki } from './helpers/pki.ts';
import { https } from './helpers/https.ts';

const pki = createPki();
const leaf = pki.leaf(PROTOCOL.issuer_name);
const secrets = (p: string) => { if (p === '/run/secrets/tls.crt') return Buffer.from(leaf.cert); if (p === '/run/secrets/tls.key') return Buffer.from(leaf.key); throw new Error('missing'); };
const rid = () => hex(randomBytes(16));
type Json = Record<string, any>;

class Harness {
  now = 1000;
  role: IssuerRole;
  runId = rid();
  manifest: Manifest | null = null;
  digest: string | null = null;
  vouchers: Buffer[] = [];
  constructor(options: ConstructorParameters<typeof IssuerRole>[0] = {}) {
    this.role = new IssuerRole({ readSecret: secrets, clock: () => this.now, listen: { host: '127.0.0.1', port: 0 }, drainMs: 500, ...options });
  }
  send(command: string, payload: Json = {}, over: Json = {}): Promise<Json> {
    return this.role.handle({ version: 1, request_id: rid(), command, run_id: this.runId, config_digest: this.digest,
      target_incarnation: this.role.incarnation, payload, ...over });
  }
  async create(over: Json = {}) { return this.send('CREATE_ISSUER_KEY', {}, { config_digest: null, ...over }); }
  async prepare(count = 4, over: { role_config?: Json; manifest?: Manifest } = {}) {
    const key = await this.create();
    assert.equal(key['ok'], true, JSON.stringify(key));
    this.manifest = makeManifest({ run_id: this.runId, run_start_ms: Date.now(), token_key_spki_b64url: key['data'].token_key_spki_b64url,
      snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40), inventory_total: count });
    const manifest = over.manifest ?? this.manifest;
    const res = await this.send('PREPARE_RUN', { manifest, proposed_config_digest: configurationDigest(manifest), role: 'issuer',
      role_config: over.role_config ?? { tls_cert_path: '/run/secrets/tls.crt', tls_key_path: '/run/secrets/tls.key' } }, { config_digest: null });
    if (res['ok']) this.digest = configurationDigest(manifest);
    this.vouchers = Array.from({ length: count }, () => randomBytes(32));
    return { key, res };
  }
  provision(index = 0, items = this.vouchers.map(voucherDigest), total = this.vouchers.length, final = true) {
    return this.send('PROVISION_VOUCHERS', { batch_id: 'c'.repeat(32), batch_index: index, expected_total: total, final_batch: final, items });
  }
  async toEnabled(count = 4) { await this.prepare(count); await this.provision(); await this.send('CHECK_READY'); return this.send('ENABLE'); }
  stop() { return this.role.handle({ version: 1, request_id: rid(), command: 'FENCE', run_id: null, config_digest: null, target_incarnation: null, payload: { reason: 'test-cleanup' } }); }
  issue(voucher: Buffer, issuance: LabIssuance) {
    return https(this.role.address!.port, pki.caPem, { method: 'POST', path: '/issue', body: issuance.requestWire,
      headers: { 'Content-Type': REQUEST_TYPE, 'X-Lab-Voucher': encodeBase64Url(voucher, false) } });
  }
}
const ok = (r: Json, result: string) => { assert.equal(r['ok'], true, JSON.stringify(r)); assert.equal(r['result'], result); validateControlResponse(r); };
const fails = (r: Json, result: string) => { assert.equal(r['ok'], false, JSON.stringify(r)); assert.equal(r['result'], result); validateControlResponse(r); };
const status = (h: Harness): Promise<Json> => h.role.handle({ version: 1, request_id: rid(), command: 'STATUS', run_id: null, config_digest: null, target_incarnation: null, payload: {} });

test('discovery, then full lifecycle to a real issuance and a strong FENCE', async () => {
  const h = new Harness();
  const s0 = await status(h);
  ok(s0, 'STATUS'); assert.equal(s0['incarnation'], h.role.incarnation); assert.equal(s0['state'], 'FENCED');
  assert.deepEqual(s0['data'], { ready: false, run_closed: false, fault: null });
  const { key, res } = await h.prepare(4);
  ok(key, 'KEY_CREATED'); ok(res, 'PREPARED');
  assert.equal(key['data'].token_key_id, h.manifest!.token_key_id);
  ok(await h.provision(0, h.vouchers.slice(0, 2).map(voucherDigest), 4, false), 'PROVISIONED');
  fails(await h.send('CHECK_READY'), 'ILLEGAL_STATE'); // not sealed
  const p2 = await h.provision(1, h.vouchers.slice(2).map(voucherDigest), 4, true);
  ok(p2, 'PROVISIONED'); assert.deepEqual(p2['data'], { received_total: 4, sealed: true });
  const ready = await h.send('CHECK_READY'); ok(ready, 'READY'); assert.deepEqual(ready['data'], { workers_ready: 1 });
  assert.equal(h.role.address, null, 'READY is not ENABLED: nothing listens yet');
  const en = await h.send('ENABLE'); ok(en, 'ENABLED'); assert.deepEqual(en['data'], { workers_enabled: 1 });
  const issuance = await LabIssuance.begin(challengeFor(h.manifest!, 0), Buffer.from(key['data'].token_key_spki_b64url, 'base64url'));
  const res200 = await h.issue(h.vouchers[0]!, issuance);
  assert.equal(res200.status, 200);
  assert.equal(await verifyTokenSignature(Buffer.from(key['data'].token_key_spki_b64url, 'base64url'), await issuance.finalize(res200.body)), true);
  const rep = h.role.report(rid()) as Json; ok(rep, 'REPORT');
  assert.deepEqual(rep['data'].counters, { issuance_successes: 1, issuance_failures: 0 });
  ok(await h.send('HEARTBEAT', { seq: 1 }), 'HEARTBEAT_ACK');
  const second = await LabIssuance.begin(challengeFor(h.manifest!, 0), Buffer.from(key['data'].token_key_spki_b64url, 'base64url'));
  const port = h.role.address!.port;
  const fence = await h.send('FENCE', { reason: 'operator-stop' }); ok(fence, 'FENCED'); assert.equal(fence['state'], 'FENCED');
  await assert.rejects(https(port, pki.caPem, { method: 'POST', path: '/issue', body: second.requestWire, headers: { 'Content-Type': REQUEST_TYPE, 'X-Lab-Voucher': encodeBase64Url(h.vouchers[1]!, false) } }), 'listener is gone');
  const after = await status(h);
  assert.deepEqual(after['data'], { ready: false, run_closed: true, fault: 'operator-stop' });
  ok(await h.send('FENCE', { reason: 'operator-stop' }), 'FENCED'); // idempotent
});

test('a closed run can never be re-created, re-prepared or re-enabled', async () => {
  const h = new Harness();
  await h.toEnabled();
  ok(await h.send('FENCE', { reason: 'test-cleanup' }), 'FENCED');
  fails(await h.create(), 'ILLEGAL_STATE');
  fails(await h.send('ENABLE'), 'ILLEGAL_STATE');
  fails(await h.send('CHECK_READY'), 'ILLEGAL_STATE');
  fails(await h.send('PREPARE_RUN', { manifest: h.manifest, proposed_config_digest: h.digest, role: 'issuer', role_config: {} }, { config_digest: null }), 'ILLEGAL_STATE');
});

test('envelope checks: version, schema, incarnation, run, digest', async () => {
  const h = new Harness();
  await h.prepare(2);
  fails(await h.role.handle({ version: 2, request_id: rid(), command: 'STATUS' }), 'BAD_VERSION');
  fails(await h.role.handle({ version: 1, request_id: rid(), command: 'STATUS', extra: 1 }), 'BAD_MESSAGE');
  fails(await h.role.handle('garbage'), 'BAD_VERSION');
  fails(await h.send('CHECK_READY', {}, { target_incarnation: rid() }), 'WRONG_INCARNATION');
  fails(await h.send('CHECK_READY', {}, { target_incarnation: null }), 'BAD_MESSAGE'); // only STATUS/FENCE may omit the target
  fails(await h.send('CHECK_READY', {}, { run_id: rid() }), 'WRONG_RUN');
  fails(await h.send('CHECK_READY', {}, { config_digest: '0'.repeat(64) }), 'WRONG_CONFIG');
  fails(await h.send('RUN_SCENARIO', { scenario_id: 'healthy-flow', schedule_seed: 1 }), 'ILLEGAL_STATE');
  const stale = await h.send('STATUS', {}, { run_id: rid(), config_digest: '0'.repeat(64) });
  ok(stale, 'STATUS'); // discovery tolerates stale memory of the caller
});

test('PREPARE binds the manifest to the key this process generated, and reports the key only as public data', async () => {
  const other = new Harness(); await other.prepare(2);
  const h = new Harness();
  const key = await h.create();
  const foreign = makeManifest({ run_id: h.runId, run_start_ms: Date.now(), token_key_spki_b64url: other.manifest!.token_key_spki_b64url,
    snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40), inventory_total: 2 });
  const res = await h.send('PREPARE_RUN', { manifest: foreign, proposed_config_digest: configurationDigest(foreign), role: 'issuer',
    role_config: { tls_cert_path: '/run/secrets/tls.crt', tls_key_path: '/run/secrets/tls.key' } }, { config_digest: null });
  fails(res, 'WRONG_CONFIG');
  const wrongRole = await h.send('PREPARE_RUN', { manifest: foreign, proposed_config_digest: configurationDigest(foreign), role: 'gateway', role_config: {} }, { config_digest: null });
  assert.equal(wrongRole['ok'], false);
  assert.deepEqual(Object.keys(key['data']).sort(), ['token_key_id', 'token_key_spki_b64url']);
  const everything = JSON.stringify([key, res]);
  assert.doesNotMatch(everything, /PRIVATE|"d"|"dp"|"dq"|"qi"/);
});

test('duplicate CREATE_ISSUER_KEY with the same request returns the same key; a different request never mints another', async () => {
  const h = new Harness();
  const id = rid();
  const send = () => h.role.handle({ version: 1, request_id: id, command: 'CREATE_ISSUER_KEY', run_id: h.runId, config_digest: null, target_incarnation: h.role.incarnation, payload: {} });
  const first = await send(); const again = await send();
  ok(first, 'KEY_CREATED');
  assert.deepEqual(again['data'], first['data']);
  fails(await h.create(), 'ILLEGAL_STATE');
  fails(await h.create({ run_id: rid() }), 'ILLEGAL_STATE');
});

test('missing TLS material is a dependency failure, not a partially prepared run', async () => {
  const h = new Harness();
  const { res } = await h.prepare(2, { role_config: { tls_cert_path: '/run/secrets/nope.crt', tls_key_path: '/run/secrets/tls.key' } });
  fails(res, 'DEPENDENCY_UNAVAILABLE');
  fails(await h.send('CHECK_READY', {}, { config_digest: '0'.repeat(64) }), 'WRONG_CONFIG'); // no digest was accepted
  const h2 = new Harness();
  const { res: res2 } = await h2.prepare(2, { role_config: {} });
  fails(res2, 'BAD_MESSAGE');
});

test('no provisioning after enable, none before prepare, no ENABLE before READY', async () => {
  const h = new Harness();
  fails(await h.send('PROVISION_VOUCHERS', { batch_id: 'c'.repeat(32), batch_index: 0, expected_total: 1, final_batch: true, items: ['1'.repeat(64)] }, { run_id: rid(), config_digest: '0'.repeat(64) }), 'WRONG_RUN');
  await h.prepare(2);
  fails(await h.send('ENABLE'), 'ILLEGAL_STATE');
  await h.provision(); await h.send('CHECK_READY');
  ok(await h.send('ENABLE'), 'ENABLED');
  fails(await h.provision(1, [], 2, true), 'ILLEGAL_STATE');
  await h.stop();
});

test('lease: first ENABLE installs it, repeat ENABLE never renews, expiry is judged before any renewal', async () => {
  const lease = PROTOCOL.gateway_common.controller_lease_ms;
  const h = new Harness();
  await h.toEnabled(2);
  const keep = h.role.address!.port;
  ok(await h.send('HEARTBEAT', { seq: 1 }), 'HEARTBEAT_ACK');
  fails(await h.send('HEARTBEAT', { seq: 1 }), 'BAD_MESSAGE'); // sequence must increase
  fails(await h.send('HEARTBEAT', { seq: 0 }), 'BAD_MESSAGE');
  h.now += lease - 500;
  ok(await h.send('ENABLE'), 'ENABLED'); // acknowledges only
  h.now += 600; // 3100 ms since the last real heartbeat
  const late = await h.send('HEARTBEAT', { seq: 2 });
  fails(late, 'FAULTED'); assert.equal(late['state'], 'FAULTED');
  assert.deepEqual((await status(h))['data'], { ready: false, run_closed: true, fault: 'lease-expired' });
  fails(await h.send('HEARTBEAT', { seq: 3 }), 'FAULTED'); // cannot be revived
  fails(await h.send('ENABLE'), 'ILLEGAL_STATE');
  await assert.rejects(https(keep, pki.caPem, { path: '/.well-known/private-token-issuer-directory' }), 'admission closed on expiry');
  ok(await h.send('FENCE', { reason: 'lease-expired' }), 'FENCED');
  assert.equal((await status(h))['data'].run_closed, true);
});

test('watchdog closes admission without any further message (controller loss)', { timeout: 15000 }, async () => {
  const h = new Harness({ clock: () => performance.now() });
  await h.toEnabled(2);
  const port = h.role.address!.port;
  assert.equal((await https(port, pki.caPem, { path: '/.well-known/private-token-issuer-directory' })).status, 200);
  await new Promise((r) => setTimeout(r, PROTOCOL.gateway_common.controller_lease_ms + 400));
  assert.equal(h.role.state, 'FAULTED');
  await assert.rejects(https(port, pki.caPem, { path: '/.well-known/private-token-issuer-directory' }));
  await h.stop();
});

test('ENABLE fails closed if the listener cannot bind', async () => {
  const a = new Harness(); await a.toEnabled(2);
  const taken = a.role.address!.port;
  const b = new Harness({ listen: { host: '127.0.0.1', port: taken } });
  await b.prepare(2); await b.provision(); await b.send('CHECK_READY');
  fails(await b.send('ENABLE'), 'FAULTED');
  assert.deepEqual((await status(b))['data'], { ready: false, run_closed: true, fault: 'dependency-lost' });
  await a.stop();
});

test('FENCE on a role that never had a run does not latch a closed run', async () => {
  const h = new Harness();
  ok(await h.stop(), 'FENCED');
  assert.deepEqual((await status(h))['data'], { ready: false, run_closed: false, fault: null });
  ok(await h.create(), 'KEY_CREATED');
});

test('a watchdog that fires early is re-armed, not forgotten; STATUS sees an expired lease without any timer', async () => {
  const lease = PROTOCOL.gateway_common.controller_lease_ms;
  const timers: { ms: number; cb: () => void; cancelled: boolean }[] = [];
  const schedule = (ms: number, cb: () => void) => { const t = { ms, cb, cancelled: false }; timers.push(t); return { cancel: () => { t.cancelled = true; } }; };
  const h = new Harness({ schedule });
  await h.toEnabled(2);
  const live = () => timers.filter((t) => !t.cancelled);
  assert.equal(live().length, 1, 'one watchdog armed by ENABLE');
  // The timer fires 1 ms early: the clock has not reached expiry. The issuer must keep enforcing.
  h.now += lease - 1;
  live()[0]!.cb();
  assert.equal(h.role.state, 'ENABLED');
  assert.ok(live().length >= 1 && live().some((t) => t.ms <= 2), 'early firing re-armed for the remainder');
  // Time passes with no heartbeat and the re-armed timer fires on time.
  h.now += 5;
  live().at(-1)!.cb();
  assert.equal(h.role.state, 'FAULTED');
  assert.deepEqual((await status(h))['data'], { ready: false, run_closed: true, fault: 'lease-expired' });
  // Separately: even with no timer firing at all, the next command of any kind judges expiry first.
  const g = new Harness({ schedule: () => ({ cancel() { /* timer never fires */ } }) });
  await g.toEnabled(2);
  g.now += lease + 1;
  assert.deepEqual((await status(g))['data'], { ready: false, run_closed: true, fault: 'lease-expired' });
  await g.stop(); await h.stop();
});
