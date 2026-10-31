import test from 'node:test';
import assert from 'node:assert/strict';
import { admissionLimitsWith, BURST, STALLED } from '../src/client/admission-scenario.ts';
import type { ScenarioContext } from '../src/client/control.ts';

type R = { status: number; label: string | null };
function rig(over: { busy?: number; retry?: (n: number) => R; stall?: { closed: boolean; ms: number }; challenge?: boolean; vouchers?: number; odd?: boolean } = {}) {
  let t = 1_000, seen = 0, redeems = 0;
  const busyIdx = new Set(Array.from({ length: over.busy ?? 5 }, (_, i) => i));
  const client = {
    async fetchChallenge() { if (over.challenge === false) throw new Error('down'); return { epoch: 0, challenge: {} }; },
    async issueWire() { return Uint8Array.of(seen++); },
    async redeemWire(w: Uint8Array) {
      redeems++;
      if (redeems <= BURST) return over.odd && w[0] === 0 ? { status: 418, label: null } : busyIdx.has(w[0]!) ? { status: 503, label: 'gateway-busy' } : { status: 200, label: null };
      return over.retry ? over.retry(redeems) : { status: 200, label: null };
    },
    async rawGateway() { const s = over.stall ?? { closed: true, ms: 2000 }; const s0 = t; await Promise.resolve(); t = Math.max(t, s0 + s.ms); return { status: null, label: null, closed: s.closed }; },
  };
  const ctx = { client, hasVoucher: (n: number) => (over.vouchers ?? 99) >= n, signal: new AbortController().signal } as unknown as ScenarioContext;
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
