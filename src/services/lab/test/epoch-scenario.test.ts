import test from 'node:test';
import assert from 'node:assert/strict';
import { epochBoundaryWith } from '../src/client/epoch-scenario.ts';
import type { ScenarioContext } from '../src/client/control.ts';

type Redeem = { status: number; label: string | null; wwwAuthenticate: string[] };
const r = (status: number, label: string | null = null): Redeem => ({ status, label, wwwAuthenticate: [] });

function rig(over: { epochs?: number[]; redeem?: (wire: Uint8Array, n: number) => Redeem; vouchers?: number } = {}) {
  const epochs = [...(over.epochs ?? [0, 0, 0, 1])];
  let redeems = 0, issued = 0;
  const client = {
    async fetchChallenge() { const epoch = epochs.length > 1 ? epochs.shift()! : epochs[0]!; return { epoch, challenge: { epoch } }; },
    async issueWire(c: { epoch: number }) { issued++; return Uint8Array.of(c.epoch, issued); },
    async redeemWire(wire: Uint8Array) { redeems++; return over.redeem ? over.redeem(wire, redeems) : redeems === 2 ? r(401, 'token-expired') : r(200); },
  };
  const ctx = { client, hasVoucher: (n: number) => (over.vouchers ?? 9) >= n, signal: new AbortController().signal } as unknown as ScenarioContext;
  let t = 0;
  return { ctx, deps: { sleep: async (ms: number) => { t += ms; }, now: () => t }, issued: () => issued };
}

test('a stale epoch-0 token is refused after the boundary and the new epoch is accepted: PASS', async () => {
  const x = rig();
  const o = await epochBoundaryWith(x.ctx, x.deps);
  assert.equal(o.status, 'PASS'); assert.equal(o.counters?.claims_successful, 2); assert.equal(o.counters?.requests_rejected, 1);
});

test('a stale token that is ACCEPTED after the boundary is a FAIL', async () => {
  const x = rig({ redeem: () => r(200) });
  assert.equal((await epochBoundaryWith(x.ctx, x.deps)).status, 'FAIL');
});

test('the old epoch not serving before the boundary makes "refused afterwards" meaningless: FAIL, not PASS', async () => {
  const x = rig({ redeem: (_w, n) => (n === 1 ? r(401, 'token-invalid') : n === 2 ? r(401, 'token-expired') : r(200)) });
  assert.equal((await epochBoundaryWith(x.ctx, x.deps)).status, 'FAIL');
});

test('the boundary never arriving within the bound is INCONCLUSIVE; too few vouchers is INCONCLUSIVE', async () => {
  const never = rig({ epochs: [0] });
  assert.equal((await epochBoundaryWith(never.ctx, never.deps)).status, 'INCONCLUSIVE');
  assert.equal((await epochBoundaryWith(rig({ vouchers: 2 }).ctx, rig().deps)).status, 'INCONCLUSIVE');
});

test('an epoch that jumped by more than one is not accepted as "the next epoch"', async () => {
  const x = rig({ epochs: [0, 0, 2] });
  assert.equal((await epochBoundaryWith(x.ctx, x.deps)).status, 'FAIL');
});
