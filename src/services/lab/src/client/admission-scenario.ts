// S10 admission-limits, client part. Run by all five clients at once so the load reaches the gateway together:
//   1. slow clients: incomplete requests must be closed by the gateway within its request timeout while a fresh challenge is
//      still served (a stalled socket must not starve everyone else);
//   2. burst: a set of distinct, genuinely signed tokens is presented at one synchronized instant. Some may be answered
//      503 `gateway-busy` (queue full or queue wait exceeded);
//   3. every token that was refused as busy is presented again, one at a time. It must be accepted exactly once: a busy
//      refusal must never have consumed the token (queue timeout or disconnection before promotion creates no claim).
// The controller adds the independent half: origin arrivals must equal the successful presentations (plus, at most, the
// tokens whose outcome the client genuinely could not see), and some refusal must have actually happened, otherwise nothing
// was bounded and the result is not a pass.
import type { ScenarioContext, ScenarioOutcome } from './control.ts';

export const BURST = 24, STALLED = 10, FIRE_TICK_MS = 15_000, STALL_BOUND_MS = 7500, STALL_MIN_MS = 500, MINT_PACE_MS = 250;
export type AdmissionDeps = { sleep: (ms: number, signal: AbortSignal) => Promise<void>; now: () => number };
const real: AdmissionDeps = {
  sleep: (ms, signal) => new Promise((resolve) => {
    if (signal.aborted) return resolve();
    let timer: NodeJS.Timeout;
    const done = () => { clearTimeout(timer); signal.removeEventListener('abort', done); resolve(); };
    timer = setTimeout(done, ms);
    signal.addEventListener('abort', done, { once: true });
  }),
  now: () => Date.now(),
};
const PARTIAL = Buffer.from('GET /resource HTTP/1.1\r\nHost: origin.lab.test\r\nX-Slow: ', 'latin1'); // no terminating blank line
type Answer = { status: number; label: string | null };
const lostAnswer: Answer = { status: 0, label: null };
const inconclusive = (label: string): ScenarioOutcome => ({ status: 'INCONCLUSIVE', expected: 'bounded', failure_labels: [label] });

export async function admissionLimitsWith(ctx: ScenarioContext, d: AdmissionDeps = real): Promise<ScenarioOutcome> {
  const { client, signal } = ctx;
  if (!ctx.hasVoucher(BURST)) return inconclusive('missing-evidence');

  // Mint first, so the burst consists of ready tokens and nothing else.
  const parsed = await client.fetchChallenge();
  const wires: Uint8Array[] = [];
  try {
    // Paced: five clients minting 24 tokens each at full speed starve the issuer's control heartbeat on a small host, and the
    // supervision deadline (never lengthened) would then close the run. The burst below is the load under test, not this.
    for (let i = 0; i < BURST; i++) {
      if (signal.aborted) return inconclusive('missing-evidence');
      wires.push(await client.issueWire(parsed.challenge)); await d.sleep(MINT_PACE_MS, signal);
    }

    // Phase 1: slow clients, while a legitimate challenge request is made in the middle of it.
    const stalls = Promise.all(Array.from({ length: STALLED }, async () => {
      const t = d.now(); const r = await client.rawGateway(PARTIAL, { timeoutMs: STALL_BOUND_MS + 1500 });
      return { connected: r.connected, closed: r.closed, ms: d.now() - t };
    }));
    await d.sleep(500, signal);
    const duringStall = await client.fetchChallenge().then(() => true, () => false);
    const stalled = await stalls;
    // A failed connection is not a gateway timeout: only sockets that were really connected, and then closed after a plausible
    // delay and within the bound, count as evidence. With none connected nothing was tested.
    const connected = stalled.filter((s) => s.connected);
    if (connected.length === 0 || signal.aborted) return inconclusive('missing-evidence');
    const bounded = connected.every((s) => s.closed && s.ms >= STALL_MIN_MS && s.ms <= STALL_BOUND_MS);

    // Phase 2: synchronized burst.
    const fireAt = Math.ceil((d.now() + 500) / FIRE_TICK_MS) * FIRE_TICK_MS;
    await d.sleep(Math.max(0, fireAt - d.now()), signal);
    if (signal.aborted) return inconclusive('missing-evidence');
    const first: Answer[] = await Promise.all(wires.map((w) => client.redeemWire(w).catch(() => lostAnswer)));
    const isBusy = (r: Answer) => r.status === 503 && r.label === 'gateway-busy';
    const busy = first.flatMap((r, i) => (isBusy(r) ? [i] : []));
    const lost = first.flatMap((r, i) => (r.status === 0 ? [i] : []));
    const unexpected = first.filter((r) => r.status !== 200 && r.status !== 0 && !isBusy(r)).length;

    // Phase 3: a busy refusal consumed nothing. A token whose first answer never arrived is presented once more: a 200 proves
    // the first attempt claimed nothing; anything else leaves its outcome unknown to the client, and the origin counter decides.
    let retriedOk = 0, retryWrong = 0, unknownOutcome = 0;
    for (const i of busy) {
      if (signal.aborted) return inconclusive('missing-evidence');
      const r: Answer = await client.redeemWire(wires[i]!).catch(() => lostAnswer);
      if (r.status === 200) retriedOk++; else retryWrong++;
    }
    for (const i of lost) {
      if (signal.aborted) return inconclusive('missing-evidence');
      const r: Answer = await client.redeemWire(wires[i]!).catch(() => lostAnswer);
      if (r.status === 200) retriedOk++; else unknownOutcome++;
    }
    const wins = first.filter((r) => r.status === 200).length + retriedOk;
    const checks = [
      { name: 'stalled clients are closed within the request timeout', ok: bounded },
      { name: 'a legitimate challenge is served while clients stall', ok: duringStall },
      { name: 'every burst answer is 200, a gateway-busy refusal or a lost connection', ok: unexpected === 0 },
      { name: 'a token refused as busy is accepted exactly once afterwards', ok: retryWrong === 0 },
    ];
    const ok = checks.every((c) => c.ok);
    return { status: ok ? 'PASS' : 'FAIL', expected: 'bounded',
      counters: { observations: checks.length + BURST, issuance_successes: BURST, claims_successful: wins, queue_rejected: busy.length, transport_failures: unknownOutcome, requests_rejected: connected.filter((s) => s.closed).length },
      failure_labels: ok ? [] : ['assertion-failed'] };
  } finally { for (const w of wires) w.fill(0); }
}
export const admissionLimits = (ctx: ScenarioContext): Promise<ScenarioOutcome> => admissionLimitsWith(ctx);
