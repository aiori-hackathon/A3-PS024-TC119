// Scenario evidence merging: the controller trusts the ORIGIN's counters, not the client's say-so.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { LabRun, ControllerError } from '../src/controller/run.ts';
import { buildReport } from '../src/report/build.ts';
import type { ScenarioRunner } from '../src/client/control.ts';
import { controllerRig, type ControllerRig } from './helpers/controller-rig.ts';

const fast = { perClient: 2, heartbeatMs: 40, ackDeadlineMs: 150, controlTimeoutMs: 3000 } as const;
const start = (rig: ControllerRig) => new LabRun({ links: rig.links, redis: rig.redis, reset: rig.reset, gatewayLauncher: rig.launcher }, fast);
const pass = (expected = 'isolated'): ScenarioRunner => async () => ({ status: 'PASS', expected, counters: { observations: 3 } });

/** Sends one fully parsed request to the rig's origin, with the given generation header (or none). */
function hitOrigin(rig: ControllerRig, header: string | null): Promise<void> {
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: '127.0.0.1', port: rig.origin.address!.port, path: '/resource', agent: false, headers: header ? { 'X-TokenForge-Run': header } : {} },
      (res) => { res.resume(); res.on('end', () => resolve()); });
    r.on('error', reject); r.end();
  });
}

test('a scenario PASS needs the origin to agree; origin deltas are merged next to the client counters', async () => {
  const rig = controllerRig({ scenarios: { 'network-boundaries': pass() } });
  const r = start(rig); await r.start();
  const rec = await r.runScenario('A', 'network-boundaries');
  assert.equal(rec.status, 'PASS');
  assert.equal(rec.origin_counts_available, true);
  assert.deepEqual([rec.counters.protected_requests_received, rec.counters.generation_mismatches, rec.counters.resources_served], [0, 0, 0]);
  assert.equal(rec.counters.observations, 3);
  await r.stop();
});

test('a client that claims PASS while the origin saw an arrival is a FAIL', async () => {
  let rig!: ControllerRig;
  const liar: ScenarioRunner = async ({ manifest }) => { await hitOrigin(rig, manifest.run_id); return { status: 'PASS', expected: 'isolated' }; };
  rig = controllerRig({ scenarios: { 'network-boundaries': liar } });
  const r = start(rig); await r.start();
  const rec = await r.runScenario('A', 'network-boundaries');
  assert.equal(rec.status, 'FAIL'); assert.deepEqual(rec.failure_labels, ['assertion-failed']);
  assert.equal(rec.counters.protected_requests_received, 1); assert.equal(rec.counters.resources_served, 1);
  await r.stop();
});

test('deltas are per scenario: earlier arrivals do not leak into a later scenario', async () => {
  let rig!: ControllerRig;
  const touch: ScenarioRunner = async ({ manifest }) => { await hitOrigin(rig, manifest.run_id); return { status: 'PASS', expected: 'accepted' }; };
  rig = controllerRig({ scenarios: { 'healthy-flow': touch, 'voucher-policy': pass('single-spend') } });
  const r = start(rig); await r.start();
  assert.equal((await r.runScenario('A', 'healthy-flow')).status, 'PASS');
  const later = await r.runScenario('B', 'voucher-policy');
  assert.equal(later.status, 'PASS', 'the earlier arrival is not counted against a scenario that did not cause it');
  assert.equal(later.counters.protected_requests_received, 0);
  await r.stop();
});

test('healthy-flow needs exactly one arrival and one served resource; two forwards or a wrong generation are failures', async () => {
  const cases: [string, (rig: ControllerRig, runId: string) => Promise<void>, string][] = [
    ['one served arrival', async (rig, id) => { await hitOrigin(rig, id); }, 'PASS'],
    ['two arrivals', async (rig, id) => { await hitOrigin(rig, id); await hitOrigin(rig, id); }, 'FAIL'],
    ['arrival with wrong generation', async (rig) => { await hitOrigin(rig, 'f'.repeat(32)); }, 'FAIL'],
    ['no arrival at all', async () => undefined, 'FAIL'],
  ];
  for (const [name, act, expected] of cases) {
    let rig!: ControllerRig;
    rig = controllerRig({ scenarios: { 'healthy-flow': async ({ manifest }) => { await act(rig, manifest.run_id); return { status: 'PASS', expected: 'accepted' }; } } });
    const r = start(rig); await r.start();
    assert.equal((await r.runScenario('A', 'healthy-flow')).status, expected, name);
    await r.stop();
  }
});

test('a gateway-dependent scenario cannot PASS without a gateway; an unimplemented scenario is not tested, never failed', async () => {
  const rig = controllerRig({ gateway: false, scenarios: { 'healthy-flow': pass('accepted') } });
  const r = new LabRun({ links: rig.links, redis: rig.redis, reset: rig.reset }, fast); await r.start();
  const healthy = await r.runScenario('A', 'healthy-flow');
  assert.equal(healthy.status, 'INCONCLUSIVE'); assert.deepEqual(healthy.failure_labels, ['missing-evidence']);
  const absent = await r.runScenario('B', 'wrong-context');
  assert.equal(absent.status, 'INCONCLUSIVE'); assert.deepEqual(absent.failure_labels, ['missing-evidence']);
  assert.equal(absent.origin_counts_available, false);
  await r.stop();
});

test('a client FAIL stays a FAIL whatever the origin shows, and a scenario with no rule is never promoted to PASS', async () => {
  const rig = controllerRig({ scenarios: { 'network-boundaries': async () => ({ status: 'FAIL', expected: 'isolated', failure_labels: ['assertion-failed'] }), 'performance': pass('rejected') } });
  const r = start(rig); await r.start();
  assert.equal((await r.runScenario('A', 'network-boundaries')).status, 'FAIL');
  const unruled = await r.runScenario('B', 'performance');
  assert.equal(unruled.status, 'INCONCLUSIVE', 'no independent origin rule exists for it yet');
  await r.stop();
});

test('the run record carries ordered transitions and builds a valid, honestly INCONCLUSIVE partial report', async () => {
  const rig = controllerRig({ scenarios: { 'voucher-policy': pass('single-spend'), 'network-boundaries': pass() } });
  const r = start(rig); await r.start();
  await r.runScenario('A', 'voucher-policy'); await r.runScenario('B', 'network-boundaries');
  await r.stop('operator-stop');
  const rec = r.runRecord()!;
  assert.deepEqual(rec.state_transitions.map((t) => t.state), ['FENCED', 'PREPARED', 'READY', 'ENABLED', 'CLOSING', 'FENCED']);
  assert.deepEqual(rec.state_transitions.map((t) => t.reason), ['startup', 'startup', 'ready', 'enabled', 'operator-stop', 'operator-stop']);
  assert.equal(rec.origin_incarnation, rig.origin.incarnation);
  assert.equal(buildReport({ kind: 'demo', runs: [rec] }).overall_status, 'INCONCLUSIVE');
});

test('before the run is enabled there is no record and scenarios are refused', async () => {
  const rig = controllerRig(); const r = start(rig);
  assert.equal(r.runRecord(), null);
  await assert.rejects(r.runScenario('A', 'voucher-policy'), (e: ControllerError) => e.code === 'setup-failed');
});

test('shared-egress: five clients must produce exactly ten distinct first spends at the origin', async () => {
  for (const [arrivals, expected] of [[2, 'PASS'], [1, 'FAIL']] as const) {
    let rig!: ControllerRig;
    const part: ScenarioRunner = async ({ manifest }) => { for (let i = 0; i < arrivals; i++) await hitOrigin(rig, manifest.run_id); return { status: 'PASS', expected: 'accepted', counters: { claims_successful: arrivals } }; };
    rig = controllerRig({ scenarios: { 'shared-egress': part } });
    const r = start(rig); await r.start();
    const rec = await r.runScenario(['A', 'B', 'C', 'D', 'E'], 'shared-egress');
    assert.equal(rec.status, expected, `${arrivals} arrivals per client`);
    assert.equal(rec.counters.protected_requests_received, arrivals * 5);
    assert.equal(rec.counters.claims_successful, arrivals * 5, 'client counters are summed across the five clients');
    await r.stop();
  }
});

test('concurrent-replay: needs exactly one arrival per winning trial AND verification attempts on every configured worker', async () => {
  const cases: [string, number[], number, string][] = [
    ['both workers verified, one win', [3, 4], 1, 'PASS'],
    ['only one worker verified', [7, 0], 1, 'FAIL'],
    ['no worker evidence at all', [], 1, 'INCONCLUSIVE'],
  ];
  for (const [name, bumps, arrivals, expected] of cases) {
    let rig!: ControllerRig;
    const scenario: ScenarioRunner = async ({ manifest }) => {
      bumps.forEach((n, i) => { rig.gateway.attempts[i] = { worker_index: i, attempts: (rig.gateway.attempts[i]?.attempts ?? 0) + n }; });
      for (let i = 0; i < arrivals; i++) await hitOrigin(rig, manifest.run_id);
      return { status: 'PASS', expected: 'single-spend', counters: { claims_successful: 1 } };
    };
    rig = controllerRig({ scenarios: { 'concurrent-replay': scenario } });
    rig.gateway.attempts = bumps.length ? [{ worker_index: 0, attempts: 0 }, { worker_index: 1, attempts: 0 }] : [];
    const r = start(rig); await r.start();
    const rec = await r.runScenario('A', 'concurrent-replay');
    assert.equal(rec.status, expected, name);
    await r.stop();
  }
  // Two winning trials reaching the origin only once is a failure of evidence, not a pass.
  let rig!: ControllerRig;
  rig = controllerRig({ scenarios: { 'concurrent-replay': async ({ manifest }) => { rig.gateway.attempts = [{ worker_index: 0, attempts: 5 }, { worker_index: 1, attempts: 5 }]; await hitOrigin(rig, manifest.run_id); return { status: 'PASS', expected: 'single-spend', counters: { claims_successful: 2 } }; } } });
  rig.gateway.attempts = [{ worker_index: 0, attempts: 0 }, { worker_index: 1, attempts: 0 }];
  const r = start(rig); await r.start();
  assert.equal((await r.runScenario('A', 'concurrent-replay')).status, 'FAIL');
  await r.stop();
});

test('malformed-token, signature-and-key and wrong-context all require ZERO origin arrivals', async () => {
  for (const id of ['malformed-token', 'signature-and-key', 'wrong-context']) {
    for (const arrive of [false, true]) {
      let rig!: ControllerRig;
      rig = controllerRig({ scenarios: { [id]: async ({ manifest }) => { if (arrive) await hitOrigin(rig, manifest.run_id); return { status: 'PASS', expected: 'rejected' }; } } });
      const r = start(rig); await r.start();
      assert.equal((await r.runScenario('A', id)).status, arrive ? 'FAIL' : 'PASS', `${id} arrive=${arrive}`);
      await r.stop();
    }
  }
});
