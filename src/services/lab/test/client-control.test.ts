import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { PROTOCOL, configurationDigest, encodeBase64Url, hex, makeManifest, validateControlResponse, type Manifest } from '../../../contracts/lib/index.ts';
import { ClientRole, baseScenarios, type ScenarioRunner } from '../src/client/control.ts';
import { startRig, type Rig } from './helpers/rig.ts';

type Json = Record<string, any>;
const rid = () => hex(randomBytes(16));
const ok = (r: Json, result: string) => { assert.equal(r['ok'], true, JSON.stringify(r)); assert.equal(r['result'], result); validateControlResponse(r); };
const fails = (r: Json, result: string) => { assert.equal(r['ok'], false, JSON.stringify(r)); assert.equal(r['result'], result); validateControlResponse(r); };

class Harness {
  role: ClientRole; runId: string; digest: string | null = null; manifest: Manifest;
  constructor(rig: Rig, scenarios?: Record<string, ScenarioRunner>) {
    this.manifest = makeManifest({ run_id: rig.manifest.run_id, run_start_ms: rig.manifest.run_start_ms, token_key_spki_b64url: rig.manifest.token_key_spki_b64url,
      snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40), client_profile: 'demo' });
    this.runId = this.manifest.run_id;
    this.role = new ClientRole({ readSecret: () => Buffer.from(rig.pki.caPem), proxy: { host: '127.0.0.1', port: rig.proxy.port }, ...(scenarios ? { scenarios } : {}), drainMs: 500 });
  }
  send(command: string, payload: Json = {}, over: Json = {}): Promise<Json> {
    return this.role.handle({ version: 1, request_id: rid(), command, run_id: this.runId, config_digest: this.digest, target_incarnation: this.role.incarnation, payload, ...over }) as Promise<Json>;
  }
  async prepare(over: Json = {}) {
    const res = await this.send('PREPARE_RUN', { manifest: this.manifest, proposed_config_digest: configurationDigest(this.manifest), role: 'client',
      role_config: { client_id: 'A', ca_cert_path: '/run/secrets/ca.crt', ...over } }, { config_digest: null });
    if (res['ok']) this.digest = configurationDigest(this.manifest);
    return res;
  }
  provision(items: string[], index = 0, total = items.length, final = true) {
    return this.send('PROVISION_CLIENT', { batch_id: 'a'.repeat(32), batch_index: index, expected_total: total, final_batch: final, items });
  }
  async toEnabled(items: string[]) { ok(await this.prepare(), 'PREPARED'); ok(await this.provision(items), 'PROVISIONED'); ok(await this.send('CHECK_READY'), 'READY'); return this.send('ENABLE'); }
  scenario(id = 'healthy-flow') { return this.send('RUN_SCENARIO', { scenario_id: id, schedule_seed: 1 }); }
  fence(reason = 'test-cleanup') { return this.send('FENCE', { reason }); }
}
const b64 = (rig: Rig, from: number, n: number) => rig.vouchers.slice(from, from + n).map((v) => encodeBase64Url(v, false));
const status = (h: Harness): Promise<Json> => h.role.handle({ version: 1, request_id: rid(), command: 'STATUS', run_id: null, config_digest: null, target_incarnation: null, payload: {} }) as Promise<Json>;

test('lifecycle to a real scenario through the proxy, then a strong FENCE that clears credentials', async () => {
  const rig = await startRig(3);
  try {
    const h = new Harness(rig);
    const s0 = await status(h);
    ok(s0, 'STATUS'); assert.deepEqual(s0['data'], { ready: false, run_closed: false, fault: null });
    fails(await h.send('CHECK_READY', {}, { config_digest: '0'.repeat(64) }), 'WRONG_RUN'); // nothing prepared yet
    ok(await h.prepare(), 'PREPARED');
    fails(await h.send('CHECK_READY'), 'ILLEGAL_STATE'); // not sealed
    ok(await h.provision(b64(rig, 0, 2), 0, 3, false), 'PROVISIONED');
    const p = await h.provision(b64(rig, 2, 1), 1, 3, true); ok(p, 'PROVISIONED'); assert.deepEqual(p['data'], { received_total: 3, sealed: true });
    fails(await h.scenario(), 'ILLEGAL_STATE'); // not enabled
    ok(await h.send('CHECK_READY'), 'READY');
    const en = await h.send('ENABLE'); ok(en, 'ENABLED');
    const done = await h.scenario();
    ok(done, 'SCENARIO_COMPLETE');
    assert.equal(done['data'].status, 'PASS'); assert.equal(done['data'].scenario_id, 'healthy-flow');
    assert.equal(done['data'].origin_counts_available, false, 'client alone cannot prove origin evidence');
    assert.equal(rig.gateway.spent.size, 1);
    const rep = await h.send('REPORT'); ok(rep, 'REPORT');
    assert.deepEqual(rep['data'].counters, { issuance_successes: 1, issuance_failures: 0, observations: 1 });
    ok(await h.fence('operator-stop'), 'FENCED');
    assert.deepEqual((await status(h))['data'], { ready: false, run_closed: true, fault: 'operator-stop' });
    fails(await h.send('ENABLE'), 'ILLEGAL_STATE');
    fails(await h.prepare(), 'ILLEGAL_STATE');
    ok(await h.fence(), 'FENCED');
  } finally { await rig.stop(); }
});

test('provisioning is bounded and one-way: no refill after enable, duplicates and bad vouchers rejected', async () => {
  const rig = await startRig(3);
  try {
    const h = new Harness(rig);
    ok(await h.prepare(), 'PREPARED');
    fails(await h.provision(['A'.repeat(42) + 'B']), 'BAD_MESSAGE');          // non-canonical pad bits
    fails(await h.provision(b64(rig, 0, 1).concat(b64(rig, 0, 1))), 'BAD_MESSAGE'); // duplicate in frame
    ok(await h.provision(b64(rig, 0, 2)), 'PROVISIONED');
    fails(await h.provision(b64(rig, 2, 1), 1, 2, true), 'ILLEGAL_STATE');      // already sealed
    ok(await h.send('CHECK_READY'), 'READY'); ok(await h.send('ENABLE'), 'ENABLED');
    fails(await h.provision(b64(rig, 2, 1), 1, 3, true), 'ILLEGAL_STATE');
    ok(await h.send('ENABLE'), 'ENABLED'); // repeat acknowledges
    await h.fence();
  } finally { await rig.stop(); }
});

test('envelope: wrong role, missing CA, wrong run/config/incarnation, issuer-only commands', async () => {
  const rig = await startRig(2);
  try {
    const h = new Harness(rig);
    fails(await h.send('PREPARE_RUN', { manifest: h.manifest, proposed_config_digest: configurationDigest(h.manifest), role: 'issuer', role_config: {} }, { config_digest: null }), 'BAD_MESSAGE');
    fails(await h.prepare({ ca_cert_path: undefined }), 'BAD_MESSAGE');
    const missing = new ClientRole({ readSecret: () => { throw new Error('nope'); } });
    fails(await missing.handle({ version: 1, request_id: rid(), command: 'PREPARE_RUN', run_id: h.runId, config_digest: null, target_incarnation: missing.incarnation,
      payload: { manifest: h.manifest, proposed_config_digest: configurationDigest(h.manifest), role: 'client', role_config: { client_id: 'A', ca_cert_path: '/run/secrets/ca.crt' } } }) as Json, 'DEPENDENCY_UNAVAILABLE');
    ok(await h.prepare(), 'PREPARED');
    fails(await h.send('CHECK_READY', {}, { target_incarnation: rid() }), 'WRONG_INCARNATION');
    fails(await h.send('CHECK_READY', {}, { run_id: rid() }), 'WRONG_RUN');
    fails(await h.send('CHECK_READY', {}, { config_digest: '0'.repeat(64) }), 'WRONG_CONFIG');
    fails(await h.send('CREATE_ISSUER_KEY', {}, { config_digest: null }), 'ILLEGAL_STATE');
    fails(await h.send('HEARTBEAT', { seq: 1 }), 'ILLEGAL_STATE');
    fails(await h.send('PROVISION_VOUCHERS', { batch_id: 'a'.repeat(32), batch_index: 0, expected_total: 1, final_batch: true, items: ['1'.repeat(64)] }), 'ILLEGAL_STATE');
    fails(await h.role.handle({ version: 2 }) as Json, 'BAD_VERSION');
    await h.fence();
  } finally { await rig.stop(); }
});

test('frozen scenarios that are not implemented refuse honestly instead of reporting a result', async () => {
  const rig = await startRig(2);
  try {
    const h = new Harness(rig);
    await h.toEnabled(b64(rig, 0, 2));
    // Pick a frozen scenario name that has no implementation yet (whichever that currently is) and prove it is refused.
    const notImplemented = PROTOCOL.scenario_ids.find((id) => !(id in baseScenarios));
    if (notImplemented) fails(await h.scenario(notImplemented), 'ILLEGAL_STATE');
    assert.ok(Object.keys(baseScenarios).every((id) => (PROTOCOL.scenario_ids as readonly string[]).includes(id)), 'only frozen scenario names exist');
    await h.fence();
  } finally { await rig.stop(); }
});

test('a stalled scenario never blocks STATUS or FENCE; FENCE aborts it and no result is reported', { timeout: 20000 }, async () => {
  const rig = await startRig(2);
  try {
    let entered!: () => void; const started = new Promise<void>((r) => { entered = r; });
    const stall: ScenarioRunner = ({ signal }) => new Promise((_resolve, reject) => { entered(); signal.addEventListener('abort', () => reject(new Error('aborted'))); });
    const h = new Harness(rig, { 'healthy-flow': stall });
    await h.toEnabled(b64(rig, 0, 2));
    const running = h.scenario();
    await started;
    fails(await h.scenario(), 'ILLEGAL_STATE'); // one scenario at a time
    ok(await status(h), 'STATUS');
    assert.equal((await status(h))['state'], 'ENABLED');
    const fence = await h.fence('operator-stop');
    ok(fence, 'FENCED');
    const late = await running;
    fails(late, 'FAULTED'); // fenced mid-scenario: no PASS/FAIL leaks out
    assert.equal(h.role.state, 'FENCED');
  } finally { await rig.stop(); }
});

test('a scenario that throws is reported as FAIL with a fixed label, never an exception message', async () => {
  const rig = await startRig(2);
  try {
    const h = new Harness(rig, { 'healthy-flow': async () => { throw new Error('secret-detail'); } });
    await h.toEnabled(b64(rig, 0, 2));
    const r = await h.scenario();
    ok(r, 'SCENARIO_COMPLETE');
    assert.equal(r['data'].status, 'FAIL');
    assert.doesNotMatch(JSON.stringify(r), /secret-detail/);
    await h.fence();
  } finally { await rig.stop(); }
});

test('S03 voucher-policy runs against the real issuer: unknown/missing refused, 422 spares the voucher, one signing per voucher', async () => {
  const rig = await startRig(2);
  try {
    const h = new Harness(rig);
    await h.toEnabled(b64(rig, 0, 2));
    const r = await h.scenario('voucher-policy');
    ok(r, 'SCENARIO_COMPLETE');
    assert.equal(r['data'].status, 'PASS', JSON.stringify(r['data']));
    assert.equal(r['data'].expected, 'single-spend');
    assert.equal(r['data'].counters.issuance_successes, 2);
    assert.equal(r['data'].origin_counts_available, false);
    // Both vouchers are spent now: the issuer refuses them if anyone tries again.
    const again = await h.scenario('voucher-policy');
    assert.equal(again['data'].status, 'INCONCLUSIVE', 'no vouchers left means no evidence, not a pass');
    assert.deepEqual(again['data'].failure_labels, ['missing-evidence']);
    await h.fence();
  } finally { await rig.stop(); }
});

test('S14 network-boundaries logic: PASS only when every path is closed and the positive control worked', async () => {
  const { networkBoundariesWith, DENIED_CONNECTS, LAB_DIRECT_TARGETS } = await import('../src/client/scenarios.ts');
  const closed = { tcp: async () => false, resolves: async () => false, connectStatus: async (a: string) => (a === 'issuer.lab.test:443' ? 200 : 403) };
  const good = await networkBoundariesWith(closed);
  assert.equal(good.status, 'PASS');
  assert.equal(good.counters?.observations, LAB_DIRECT_TARGETS.length + 4 + DENIED_CONNECTS.length);
  // A reachable origin, a resolvable name, a tunnel to an arbitrary host, or a silent proxy each fail the scenario.
  assert.equal((await networkBoundariesWith({ ...closed, tcp: async (h: string) => h === '172.28.50.10' })).status, 'FAIL');
  assert.equal((await networkBoundariesWith({ ...closed, resolves: async (n: string) => n === 'redis' })).status, 'FAIL');
  assert.equal((await networkBoundariesWith({ ...closed, connectStatus: async (a: string) => (a === 'example.com:443' || a === 'issuer.lab.test:443' ? 200 : 403) })).status, 'FAIL');
  assert.equal((await networkBoundariesWith({ ...closed, connectStatus: async (a: string) => (a === 'issuer.lab.test:443' ? 200 : null) })).status, 'FAIL', 'no reply is not a refusal');
  // If the positive control fails, the probes prove nothing.
  const blind = await networkBoundariesWith({ ...closed, connectStatus: async () => 502 });
  assert.equal(blind.status, 'INCONCLUSIVE'); assert.deepEqual(blind.failure_labels, ['missing-evidence']);
});
