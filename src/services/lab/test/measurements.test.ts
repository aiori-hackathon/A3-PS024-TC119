import test from 'node:test';
import assert from 'node:assert/strict';
import { Histogram, bucketOf, mergeMeasurements, quantile, BUCKETS } from '../src/report/histogram.ts';
import { performanceWith, TOKENS } from '../src/client/performance-scenario.ts';
import type { ScenarioContext, ScenarioRunner } from '../src/client/control.ts';
import { LabRun } from '../src/controller/run.ts';
import { buildReport } from '../src/report/build.ts';
import { controllerRig } from './helpers/controller-rig.ts';

test('buckets use the frozen bounds, with an overflow bucket; quantiles are bucket upper bounds, null in overflow or when empty', () => {
  assert.equal(BUCKETS, 15);
  assert.deepEqual([0, 0.1, 0.11, 0.5, 5000, 5000.1, Infinity, NaN, -1].map(bucketOf), [0, 0, 1, 1, 13, 14, 14, 14, 14]);
  assert.equal(quantile(new Array(15).fill(0), 0.5), null);
  const h = new Histogram(); for (let i = 0; i < 100; i++) h.add(i < 90 ? 3 : 40);
  const m = h.summary('protected_response_ms', 1234.5678);
  assert.equal(m.count, 100); assert.equal(m.p50_ms, 5); assert.equal(m.p95_ms, 50); assert.equal(m.histogram_counts.reduce((a, b) => a + b, 0), m.count);
  const tail = new Histogram(); tail.add(1); tail.add(99999);
  assert.equal(tail.summary('protected_response_ms', 1).p99_ms, null, 'a quantile inside the overflow bucket is unknown, not made up');
});

test('merging adds counts and failures, takes the longest elapsed time and recomputes quantiles', () => {
  const a = new Histogram(), b = new Histogram(); a.add(3); a.add(3); a.fail(); b.add(300); b.fail(); b.fail();
  const [m] = mergeMeasurements([[a.summary('token_acquisition_ms', 100)], [b.summary('token_acquisition_ms', 250)]]);
  assert.equal(m!.count, 3); assert.equal(m!.failures, 3); assert.equal(m!.elapsed_ms, 250); assert.equal(m!.p50_ms, 5); assert.equal(m!.p99_ms, 500);
  assert.deepEqual(mergeMeasurements([]), []);
});

function perfRig(over: { statusAt?: (i: number) => { status: number; label: string | null } | 'throw'; vouchers?: number } = {}) {
  let t = 0, minted = 0, presented = 0;
  const client = {
    async fetchChallenge() { return { epoch: 0, challenge: {} }; },
    async issueWire() { t += 4; return Uint8Array.of(minted++ & 255); },
    async redeemWire() { const i = presented++; t += 3; const r = over.statusAt?.(i) ?? { status: 200, label: null }; if (r === 'throw') throw new Error('reset'); return r; },
  };
  const ctx = { client, hasVoucher: (n: number) => (over.vouchers ?? 999) >= n, signal: new AbortController().signal } as unknown as ScenarioContext;
  return { ctx, deps: { sleep: async (ms: number) => { t += ms; }, now: () => t } };
}

test('performance: histograms hold exactly the successes; busy refusals are failures and are not retried', async () => {
  const x = perfRig({ statusAt: (i) => (i % 10 === 0 ? { status: 503, label: 'gateway-busy' } : { status: 200, label: null }) });
  const o = await performanceWith(x.ctx, x.deps);
  assert.equal(o.status, 'PASS');
  const acq = o.measurements!.find((m) => m.metric === 'token_acquisition_ms')!, resp = o.measurements!.find((m) => m.metric === 'protected_response_ms')!;
  assert.equal(acq.count, TOKENS); const busy = TOKENS / 10;
  assert.equal(resp.count, TOKENS - busy); assert.equal(resp.failures, busy);
  assert.equal(o.counters?.claims_successful, TOKENS - busy); assert.equal(o.counters?.queue_rejected, busy);
});

test('performance: an unexpected status is a FAIL, a lost connection is counted as unknown, too few vouchers is INCONCLUSIVE', async () => {
  const odd = perfRig({ statusAt: (i) => (i === 5 ? { status: 401, label: 'token-invalid' } : { status: 200, label: null }) });
  assert.equal((await performanceWith(odd.ctx, odd.deps)).status, 'FAIL');
  const lost = perfRig({ statusAt: (i) => (i === 7 ? 'throw' : { status: 200, label: null }) });
  const o = await performanceWith(lost.ctx, lost.deps);
  assert.equal(o.counters?.transport_failures, 1); assert.equal(o.counters?.claims_successful, TOKENS - 1);
  assert.equal((await performanceWith(perfRig({ vouchers: TOKENS - 1 }).ctx)).status, 'INCONCLUSIVE');
});

test('the controller merges every client\'s REPORT measurements into the run record, and the report stays schema-valid', async () => {
  const perf: ScenarioRunner = async () => {
    const h = new Histogram(); h.add(2); h.add(20);
    return { status: 'PASS', expected: 'accepted', counters: { observations: 2 }, measurements: [h.summary('protected_response_ms', 500)] };
  };
  const rig = controllerRig({ scenarios: { performance: perf } });
  const r = new LabRun({ links: rig.links, redis: rig.redis, reset: rig.reset, gatewayLauncher: rig.launcher }, { perClient: 2, heartbeatMs: 40, ackDeadlineMs: 150, controlTimeoutMs: 3000 });
  await r.start();
  const rec = await r.runScenario(['A', 'B'], 'performance');
  assert.notEqual(rec.status, 'PASS', 'no origin arrivals and no wins: the independent rule does not pass it');
  const m = r.runRecord()!.measurements as { metric: string; count: number }[];
  assert.equal(m.length, 1); assert.equal(m[0]!.metric, 'protected_response_ms'); assert.equal(m[0]!.count, 4);
  await r.stop();
  assert.doesNotThrow(() => buildReport({ kind: 'benchmark', runs: [r.runRecord()!] }));
});
