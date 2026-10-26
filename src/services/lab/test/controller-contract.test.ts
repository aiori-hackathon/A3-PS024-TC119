// Lab-controller view of the shared control/report contracts: what the controller needs must be expressible,
// and unsafe variants must be refused. Schema acceptance is not state-machine behaviour (not tested here).
import test from 'node:test';
import assert from 'node:assert/strict';
import { Ajv } from 'ajv';
import golden from '../../../contracts/fixtures/policy-golden.json' with { type: 'json' };
import requestSchema from '../../../contracts/schemas/control-request-v1.json' with { type: 'json' };
import responseSchema from '../../../contracts/schemas/control-response-v1.json' with { type: 'json' };
import reportSchema from '../../../contracts/schemas/report-v1.schema.json' with { type: 'json' };
import protocol from '../../../contracts/protocol-v1.json' with { type: 'json' };
import {
  validateControlRequest, validateControlResponse, validateReport, validateManifest, configurationDigest, encodeBase64Url,
} from '../../../contracts/lib/index.ts';

const manifest = validateManifest(golden.manifest);
const digest = configurationDigest(manifest);
const ajv = new Ajv({ strict: true, allErrors: true });
const independentRequest = ajv.compile(requestSchema);
const independentResponse = ajv.compile(responseSchema);
const independentReport = ajv.compile(reportSchema);
const id = (n: number) => n.toString(16).padStart(32, '0');
const run = manifest.run_id, inc = id(7);
const hexItems = (n: number) => Array.from({ length: n }, (_, i) => (i + 1).toString(16).padStart(64, '0'));
const b64Items = (n: number) => Array.from({ length: n }, (_, i) => encodeBase64Url(Uint8Array.from({ length: 32 }, () => i), false));
const req = (command: string, payload: object, over: object = {}) =>
  ({ version: 1, request_id: id(1), command, run_id: run, config_digest: digest, target_incarnation: inc, payload, ...over });
const accepts = (v: unknown) => { assert.doesNotThrow(() => validateControlRequest(v)); assert.equal(independentRequest(v), true, JSON.stringify(independentRequest.errors)); };
const rejects = (v: unknown, why: string) => { assert.throws(() => validateControlRequest(v), Error, why); assert.equal(independentRequest(v), false, `Ajv: ${why}`); };
// Cross-field/canonical-encoding rules that plain JSON Schema cannot express: the shared helper must refuse them,
// and the receiving role must repeat the check (a schema-valid frame is not an authorized one).
const rejectsSemantically = (v: unknown, why: string) => { assert.throws(() => validateControlRequest(v), Error, why); assert.equal(independentRequest(v), true, `schema-only gap: ${why}`); };
const batch = (items: string[], over: object = {}) => ({ batch_id: id(9), batch_index: 0, expected_total: items.length, final_batch: true, items, ...over });

test('PREPARE_RUN: initial null config digest and proposed digest, per role, as the controller will send it', () => {
  for (const role of ['issuer', 'gateway', 'origin', 'client'] as const) {
    accepts(req('PREPARE_RUN', { manifest, proposed_config_digest: digest, role, role_config: {} }, { config_digest: null }));
  }
  const paths = { tls_cert_path: '/run/secrets/tls.crt', tls_key_path: '/run/secrets/tls.key', ca_cert_path: '/run/secrets/ca.crt', redis_credential_path: '/run/secrets/redis' };
  accepts(req('PREPARE_RUN', { manifest, proposed_config_digest: digest, role: 'gateway', role_config: paths }, { config_digest: null }));
  accepts(req('PREPARE_RUN', { manifest, proposed_config_digest: digest, role: 'client', role_config: { client_id: 'E' } }, { config_digest: null }));
  const base = { manifest, proposed_config_digest: digest, role: 'issuer', role_config: {} };
  rejects(req('PREPARE_RUN', base), 'PREPARE must not carry an established digest');
  rejectsSemantically(req('PREPARE_RUN', { ...base, proposed_config_digest: '0'.repeat(64) }, { config_digest: null }), 'proposed digest must match manifest');
  rejectsSemantically(req('PREPARE_RUN', base, { config_digest: null, run_id: id(5) }), 'envelope run must match manifest run');
  rejects(req('PREPARE_RUN', { ...base, role_config: { tls_key_path: '../etc/shadow' } }, { config_digest: null }), 'secret paths are confined to /run/secrets');
  rejects(req('PREPARE_RUN', { ...base, role_config: { tls_key_path: '/run/secrets/x', secret: 'inline' } }, { config_digest: null }), 'no inline credentials');
  rejects(req('PREPARE_RUN', { ...base, manifest: { ...manifest, limits: { ...manifest.limits, gateway: { ...manifest.limits.gateway, workers: 3 } } } }, { config_digest: null }), 'manifest drift');
});

test('bounded sealed provisioning: issuer vouchers (digests) and client vouchers (secrets) up to 128 per frame', () => {
  accepts(req('PROVISION_VOUCHERS', batch(hexItems(128), { expected_total: 128 })));
  accepts(req('PROVISION_VOUCHERS', batch(hexItems(128), { expected_total: 256, final_batch: false })));
  accepts(req('PROVISION_VOUCHERS', batch([], { batch_index: 2, expected_total: 256 })), );
  accepts(req('PROVISION_CLIENT', batch(b64Items(128), { expected_total: 128 })));
  rejects(req('PROVISION_VOUCHERS', batch(hexItems(129))), '129 items per frame');
  rejects(req('PROVISION_CLIENT', batch(b64Items(129))), '129 items per frame');
  rejects(req('PROVISION_VOUCHERS', batch(hexItems(1), { final_batch: undefined })), 'seal flag required');
  rejects(req('PROVISION_VOUCHERS', batch(hexItems(1), { expected_total: undefined })), 'expected total required');
  rejects(req('PROVISION_VOUCHERS', batch(hexItems(1), { expected_total: protocol.client_profiles.benchmark.inventory_max + 1 })), 'total above benchmark inventory');
  rejects(req('PROVISION_VOUCHERS', batch(['A'.repeat(64)])), 'digests are lowercase hex');
  rejects(req('PROVISION_CLIENT', batch(['A'.repeat(42)])), 'voucher must be exactly 43 base64url characters');
  rejects(req('PROVISION_CLIENT', batch(['A'.repeat(43) + '='])), 'no padding');
  // Canonical pad bits: 43 chars carry 258 bits; last char must have low 2 bits clear ('B' = 000001 does not).
  rejectsSemantically(req('PROVISION_CLIENT', batch(['A'.repeat(42) + 'B'])), 'non-canonical pad bits');
});

test('lease: ENABLE and HEARTBEAT carry no renewal fields; heartbeat sequence is positive and bounded', () => {
  accepts(req('ENABLE', {}));
  rejects(req('ENABLE', { lease_ms: 3000 }), 'lease length is policy, not a request field');
  accepts(req('HEARTBEAT', { seq: 1 }));
  accepts(req('HEARTBEAT', { seq: Number.MAX_SAFE_INTEGER }));
  rejects(req('HEARTBEAT', { seq: 0 }), 'seq starts at 1');
  rejects(req('HEARTBEAT', { seq: 1.5 }), 'integer seq');
  rejects(req('HEARTBEAT', {}), 'seq required');
  rejects(req('ENABLE', {}, { config_digest: null }), 'ENABLE requires the established digest');
  rejects(req('HEARTBEAT', { seq: 1 }, { target_incarnation: null }), 'no unaddressed heartbeats');
});

test('FENCE and STATUS are addressable with and without run identity (emergency fence needs no run)', () => {
  for (const reason of protocol.faults) accepts(req('FENCE', { reason }, { run_id: null, config_digest: null, target_incarnation: null }));
  accepts(req('FENCE', { reason: 'operator-stop' }));
  accepts(req('STATUS', {}, { run_id: null, config_digest: null, target_incarnation: null }));
  rejects(req('FENCE', { reason: 'because' }), 'closed reason set');
  rejects(req('FENCE', {}), 'reason required');
  rejects(req('STATUS', { verbose: true }), 'no extension payload');
});

test('CREATE_ISSUER_KEY / RUN_SCENARIO / CHECK_READY / REPORT shapes', () => {
  accepts(req('CREATE_ISSUER_KEY', {}, { config_digest: null }));
  rejects(req('CREATE_ISSUER_KEY', {}), 'key creation precedes the digest');
  accepts(req('CHECK_READY', {}));
  accepts(req('REPORT', {}));
  for (const scenario_id of protocol.scenario_ids) accepts(req('RUN_SCENARIO', { scenario_id, schedule_seed: 4294967295 }));
  rejects(req('RUN_SCENARIO', { scenario_id: 'arbitrary-shell', schedule_seed: 1 }), 'named scenarios only');
  rejects(req('RUN_SCENARIO', { scenario_id: 'healthy-flow', schedule_seed: 4294967296 }), 'seed bound');
  rejects(req('UNKNOWN_COMMAND', {}), 'closed command set');
  rejects({ ...req('STATUS', {}), extra: 1 }, 'no unknown envelope fields');
});

test('control frames respect the shared 65536-byte limit', () => {
  const ok = req('PROVISION_CLIENT', batch(b64Items(128), { expected_total: 128 }));
  assert.ok(Buffer.byteLength(JSON.stringify(ok)) < protocol.control_message_max_bytes);
  // A full PREPARE with the golden manifest also fits comfortably.
  const prep = req('PREPARE_RUN', { manifest, proposed_config_digest: digest, role: 'gateway', role_config: {} }, { config_digest: null });
  assert.ok(Buffer.byteLength(JSON.stringify(prep)) < protocol.control_message_max_bytes);
});

const reply = (result: string, data: object, over: object = {}) =>
  ({ version: 1, request_id: id(1), state: 'READY', run_id: run, config_digest: digest, incarnation: inc, ok: true, result, data, ...over });

test('responses the controller must interpret: sealed provisioning, readiness with worker count, enable, status/fault', () => {
  const good = [
    reply('KEY_CREATED', { token_key_spki_b64url: manifest.token_key_spki_b64url, token_key_id: manifest.token_key_id }, { state: 'FENCED', config_digest: null }),
    reply('PREPARED', {}, { state: 'PREPARED' }),
    reply('PROVISIONED', { received_total: 128, sealed: true }, { state: 'PREPARED' }),
    reply('READY', { workers_ready: manifest.limits.gateway.workers }),
    reply('ENABLED', { workers_enabled: manifest.limits.gateway.workers }, { state: 'ENABLED' }),
    reply('HEARTBEAT_ACK', { seq: 5 }, { state: 'ENABLED' }),
    reply('FENCED', {}, { state: 'FENCED', run_id: null, config_digest: null }),
    reply('STATUS', { ready: true, run_closed: false, fault: null }, { state: 'ENABLED' }),
    reply('STATUS', { ready: false, run_closed: true, fault: 'lease-expired' }, { state: 'FAULTED' }),
  ];
  for (const r of good) {
    assert.doesNotThrow(() => validateControlResponse(r), JSON.stringify(r));
    assert.equal(independentResponse(r), true, JSON.stringify(independentResponse.errors));
  }
  const bad = [
    reply('PROVISIONED', { received_total: 128 }),
    reply('READY', { workers_ready: 1, token: 'leak' }),
    reply('ENABLED', { workers_enabled: 1 }, { state: 'LIMBO' }),
    { ...reply('READY', { workers_ready: 1 }), private_key: 'x' },
  ];
  for (const r of bad) {
    assert.throws(() => validateControlResponse(r), Error, JSON.stringify(r));
    assert.equal(independentResponse(r), false);
  }
});

test('report: PASS needs every required scenario and independent origin evidence; partial/live reports stay non-PASS', () => {
  const counters = { verification_attempts: 1, claims_successful: 1, replays_rejected: 0, requests_rejected: 0, queue_rejected: 0,
    transport_failures: 0, protected_requests_received: 1, generation_mismatches: 0, resources_served: 1,
    issuance_successes: 1, issuance_failures: 0, observations: 1 };
  const scenario = (scenario_id: string, status = 'PASS', origin = true) => ({ scenario_id, status, expected: 'accepted', counters,
    origin_counts_available: origin, worker_verification_attempts: [{ worker_index: 0, attempts: 1 }], failure_labels: [] });
  const report = (ids: string[], overall: string, over: { origin?: boolean } = {}) => ({
    schema_version: 1, contract_version: protocol.contract_version, suite_kind: 'benchmark', suite_id: id(3),
    created_at_utc: '2026-10-26T00:00:00Z',
    software: { git_commit: 'a'.repeat(40), dirty: false, node_version: '24.18.0', dependencies: { privacypass: '0.9.0', blindrsa: '0.4.5' }, image_digests: [] },
    environment: { os: 'linux', cpu_model: 'test', cpu_count: 4, memory_limit_bytes: 1 << 30, docker_version: '29.2.0', topology: 'single-host-private' },
    runs: [{ run_id: run, config_digest: digest, token_key_id: manifest.token_key_id, gateway_profile: 'B1', client_profile: 'benchmark',
      origin_incarnation: inc, scenario_results: ids.map((s) => scenario(s, 'PASS', over.origin ?? true)),
      measurements: [], state_transitions: [{ state: 'READY', reason: 'ready' }], retention_checks: [] }],
    overall_status: overall,
  });
  const ok = report(['performance'], 'PASS');
  assert.doesNotThrow(() => validateReport(ok));
  assert.equal(independentReport(ok), true, JSON.stringify(independentReport.errors));
  assert.throws(() => validateReport(report(['performance'], 'PASS', { origin: false })), { message: 'missing-evidence' });
  assert.throws(() => validateReport(report(['healthy-flow'], 'PASS')), { message: 'missing-evidence' });
  assert.throws(() => validateReport(report([], 'PASS')), { message: 'missing-evidence' });
  assert.doesNotThrow(() => validateReport(report(['healthy-flow'], 'INCONCLUSIVE')));
  assert.equal(independentReport({ ...ok, token: 'secret' }), false, 'no free-form diagnostics');
});
