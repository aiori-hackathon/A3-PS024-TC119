import test from 'node:test';
import assert from 'node:assert/strict';
import { admissionLimitsWith, BURST, STALLED } from '../src/client/admission-scenario.ts';
import type { ScenarioContext } from '../src/client/control.ts';

type R = { status: number; label: string | null };
function rig(over: { busy?: number; retry?: (n: number) => R; stall?: { closed: boolean; ms: number; connected?: boolean }; challenge?: boolean; vouchers?: number; odd?: boolean; wrongBusyLabel?: boolean; lostFirst?: number; abort?: AbortController } = {}) {
  let t = 1_000, seen = 0, redeems = 0;
  const busyIdx = new Set(Array.from({ length: over.busy ?? 5 }, (_, i) => i));
  const client = {
    async fetchChallenge() { if (over.challenge === false) throw new Error('down'); return { epoch: 0, challenge: {} }; },
    async issueWire() { return Uint8Array.of(seen++); },
    async redeemWire(w: Uint8Array) {
      redeems++;
      if (redeems <= BURST) return over.odd && w[0] === 0 ? { status: 418, label: null } : (over.lostFirst ?? 0) > w[0]! ? (() => { throw new Error('reset'); })() : busyIdx.has(w[0]!) ? { status: 503, label: over.wrongBusyLabel ? 'authorization-unavailable' : 'gateway-busy' } : { status: 200, label: null };
      return over.retry ? over.retry(redeems) : { status: 200, label: null };
    },
    async rawGateway() { const s = over.stall ?? { closed: true, ms: 2000 }; const s0 = t; await Promise.resolve(); t = Math.max(t, s0 + s.ms); return { status: null, label: null, closed: s.closed, connected: s.connected ?? true }; },
  };
  const ctx = { client, hasVoucher: (n: number) => (over.vouchers ?? 99) >= n, signal: (over.abort ?? new AbortController()).signal } as unknown as ScenarioContext;
  return { ctx, deps: { sleep: async (ms: number) => { t += ms; }, now: () => t } };
}

test('stalls are closed in time, busy refusals are retried to success: PASS with the refusals counted', async () => {
  const x = rig(); const o = await admissionLimitsWith(x.ctx, x.deps);
  assert.equal(o.status, 'PASS'); assert.equal(o.counters?.queue_rejected, 5); assert.equal(o.counters?.claims_successful, BURST); assert.equal(o.counters?.requests_rejected, STALLED);
});

test('a token refused as busy that is then refused as spent means the refusal consumed it: FAIL', async () => {
  const x = rig({ retry: () => ({ status: 401, label: 'token-already-redeemed' }) });
  assert.equal((await admissionLimitsWith(x.ctx, x.deps)).status, 'FAIL');
});

test('a stalled socket that outlives the bound, or a starved legitimate request, is a FAIL', async () => {
  const late = rig({ stall: { closed: true, ms: 9000 } });
  assert.equal((await admissionLimitsWith(late.ctx, late.deps)).status, 'FAIL');
  const slow = rig({ stall: { closed: false, ms: 1000 } });
  assert.equal((await admissionLimitsWith(slow.ctx, slow.deps)).status, 'FAIL');
  const starved = rig({ challenge: false });
  await assert.rejects(admissionLimitsWith(starved.ctx, starved.deps)); // the first challenge fetch itself fails: no result is invented
});

test('an answer that is neither success, busy nor a lost connection is a FAIL; too few vouchers is INCONCLUSIVE', async () => {
  const odd = rig({ odd: true });
  assert.equal((await admissionLimitsWith(odd.ctx, odd.deps)).status, 'FAIL');
  assert.equal((await admissionLimitsWith(rig({ vouchers: BURST - 1 }).ctx, rig().deps)).status, 'INCONCLUSIVE');
});

test('a 503 that is not gateway-busy is not an admission refusal: FAIL', async () => {
  const x = rig({ wrongBusyLabel: true });
  assert.equal((await admissionLimitsWith(x.ctx, x.deps)).status, 'FAIL');
});

test('stalls that never connected prove nothing: INCONCLUSIVE', async () => {
  const none = rig({ stall: { closed: true, ms: 100, connected: false } });
  assert.equal((await admissionLimitsWith(none.ctx, none.deps)).status, 'INCONCLUSIVE');
});

test('connections lost in the burst are retried; their unresolved outcome is reported, not hidden', async () => {
  const x = rig({ busy: 0, lostFirst: 3 });
  const o = await admissionLimitsWith(x.ctx, x.deps);
  assert.equal(o.status, 'PASS'); assert.equal(o.counters?.claims_successful, BURST); assert.equal(o.counters?.transport_failures, 0, 'each retry succeeded');
});

test('a fence mid-scenario stops it before anything more is presented', async () => {
  const abort = new AbortController(); const x = rig({ abort }); abort.abort();
  assert.equal((await admissionLimitsWith(x.ctx, x.deps)).status, 'INCONCLUSIVE');
});
