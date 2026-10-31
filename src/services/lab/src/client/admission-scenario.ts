// S10 admission-limits, client part. Run by all five clients at once so the load reaches the gateway together:
//   1. slow clients: incomplete requests must be closed by the gateway within its request timeout while a fresh challenge is
//      still served (a stalled socket must not starve everyone else);
//   2. burst: a set of distinct, genuinely signed tokens is presented at one synchronized instant. Some may be answered
//      503 `gateway-busy` (queue full or queue wait exceeded);
//   3. every token that was refused as busy is presented again, one at a time. It must be accepted exactly once: a busy
//      refusal must never have consumed the token (queue timeout or disconnection before promotion creates no claim).
// The controller adds the independent half: origin arrivals must equal the successful presentations, and some refusal must
// have actually happened, otherwise nothing was bounded and the result is not a pass.
import type { ScenarioContext, ScenarioOutcome } from './control.ts';
import type { LabClient } from './client.ts';

export const BURST = 24, STALLED = 10, FIRE_TICK_MS = 15_000, MINT_PACE_MS = 250, STALL_BOUND_MS = 7500;
export type AdmissionDeps = { sleep: (ms: number) => Promise<void>; now: () => number };
const real: AdmissionDeps = { sleep: (ms) => new Promise((r) => setTimeout(r, ms)), now: () => Date.now() };
const PARTIAL = Buffer.from('GET /resource HTTP/1.1\r\nHost: origin.lab.test\r\nX-Slow: ', 'latin1'); // no terminating blank line

export async function admissionLimitsWith(ctx: ScenarioContext, d: AdmissionDeps = real): Promise<ScenarioOutcome> {
  const { client } = ctx;
  if (!ctx.hasVoucher(BURST)) return { status: 'INCONCLUSIVE', expected: 'bounded', failure_labels: ['missing-evidence'] };

  // Mint first, so the burst consists of ready tokens and nothing else.
  const parsed = await client.fetchChallenge();
  const wires: Uint8Array[] = [];
  // Paced: five clients minting 24 tokens each at full speed starve the issuer's control heartbeat on a small host, and the
  // supervision deadline (never lengthened) would then close the run. The burst below is the load under test, not this.
  for (let i = 0; i < BURST; i++) { wires.push(await client.issueWire(parsed.challenge)); await d.sleep(MINT_PACE_MS); }
  try {
    // Phase 1: slow clients, while a legitimate challenge request is made in the middle of it.
    const stalls = Promise.all(Array.from({ length: STALLED }, async () => {
      const t = d.now(); const r = await client.rawGateway(PARTIAL, { timeoutMs: STALL_BOUND_MS + 1500 });
      return { closed: r.closed, ms: d.now() - t };
    }));
    await d.sleep(500);
    const duringStall = await client.fetchChallenge().then(() => true, () => false);
    const stalled = await stalls;
    const bounded = stalled.every((s) => s.closed && s.ms <= STALL_BOUND_MS);

    // Phase 2: synchronized burst.
    const fireAt = Math.ceil((d.now() + 500) / FIRE_TICK_MS) * FIRE_TICK_MS;
    await d.sleep(Math.max(0, fireAt - d.now()));
    const first = await Promise.all(wires.map((w) => client.redeemWire(w).catch(() => ({ status: 0, label: null as string | null }))));
    const busy = first.map((r, i) => (r.status === 503 && r.label === 'gateway-busy' ? i : -1)).filter((i) => i >= 0);
    const lost = first.map((r, i) => (r.status === 0 ? i : -1)).filter((i) => i >= 0);
    const unexpected = first.filter((r) => ![200, 503, 0].includes(r.status)).length;

    // Phase 3: a busy refusal consumed nothing.
    let retriedOk = 0, retryWrong = 0;
    for (const i of busy) { const r = await client.redeemWire(wires[i]!).catch(() => ({ status: 0, label: null as string | null })); if (r.status === 200) retriedOk++; else retryWrong++; }
    for (const i of lost) await client.redeemWire(wires[i]!).catch(() => null); // outcome unknown to the client: the origin counter decides
    const wins = first.filter((r) => r.status === 200).length + retriedOk;
    const checks = [
      { name: 'stalled clients are closed within the request timeout', ok: bounded },
      { name: 'a legitimate challenge is served while clients stall', ok: duringStall },
      { name: 'every burst answer is 200, a busy refusal or a lost connection', ok: unexpected === 0 },
      { name: 'a token refused as busy is accepted exactly once afterwards', ok: retryWrong === 0 },
    ];
    const ok = checks.every((c) => c.ok);
    return { status: ok ? 'PASS' : 'FAIL', expected: 'bounded',
      counters: { observations: checks.length + BURST, issuance_successes: BURST, claims_successful: wins, queue_rejected: busy.length, transport_failures: lost.length, requests_rejected: stalled.filter((s) => s.closed).length },
      failure_labels: ok ? [] : ['assertion-failed'] };
  } finally { for (const w of wires) w.fill(0); }
}
export const admissionLimits = (ctx: ScenarioContext): Promise<ScenarioOutcome> => admissionLimitsWith(ctx);
