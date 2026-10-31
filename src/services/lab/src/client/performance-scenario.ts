// S18 performance (client part). The same declared load runs against the B0 and the B1 gateway, with identical security
// semantics, and only aggregates leave this file: two fixed-bucket histograms (token acquisition and protected response) with
// counts, failures and elapsed time. Method:
//   * Every client first mints TOKENS tokens, paced (a burst of minting from five clients would starve the issuer's control
//     heartbeat, and the supervision deadline is never lengthened). Minting is timed as `token_acquisition_ms`
//     (blinding + issuer POST + finalization + public verification, for one token).
//   * Then each client presents its tokens once each, with WORKERS requests in flight, as one closed loop. The latency of a
//     request is `protected_response_ms` (client side: request start to complete response). A 503 `gateway-busy` is counted as a
//     failure and is NOT retried, so the number is the declared load's honest result. Total in flight is clients x WORKERS = 15,
//     which fits the one-worker B0 gateway (1 active flow + 16 queued) so both profiles face the same load.
// The clients and the gateway share one host and the CPU is shared with the issuer's signing, so absolute numbers describe this
// lab, not a deployment. TLS to the gateway is established per connection (keep-alive reuses connections within the pool).
import { performance } from 'node:perf_hooks';
import type { ScenarioContext, ScenarioOutcome } from './control.ts';
import { Histogram } from '../report/histogram.ts';

export const TOKENS = 80, WORKERS = 3, MINT_PACE_MS = 200;
export type PerfDeps = { sleep: (ms: number) => Promise<void>; now: () => number };
const real: PerfDeps = { sleep: (ms) => new Promise((r) => setTimeout(r, ms)), now: () => performance.now() };

export async function performanceWith(ctx: ScenarioContext, d: PerfDeps = real): Promise<ScenarioOutcome> {
  const { client, signal } = ctx;
  if (!ctx.hasVoucher(TOKENS)) return { status: 'INCONCLUSIVE', expected: 'accepted', failure_labels: ['missing-evidence'] };
  const parsed = await client.fetchChallenge();
  const acquisition = new Histogram(), response = new Histogram();
  const wires: Uint8Array[] = [];
  try {
    const mintStart = d.now();
    for (let i = 0; i < TOKENS; i++) {
      if (signal.aborted) return { status: 'INCONCLUSIVE', expected: 'accepted', failure_labels: ['missing-evidence'] };
      const t = d.now();
      try { wires.push(await client.issueWire(parsed.challenge)); acquisition.add(d.now() - t); } catch { acquisition.fail(); }
      await d.sleep(MINT_PACE_MS);
    }
    const mintElapsed = d.now() - mintStart;

    let next = 0, ok = 0, busy = 0, other = 0, lost = 0;
    const redeemStart = d.now();
    await Promise.all(Array.from({ length: WORKERS }, async () => {
      for (;;) {
        const i = next++;
        if (i >= wires.length || signal.aborted) return;
        const t = d.now();
        const r = await client.redeemWire(wires[i]!).catch(() => null);
        if (r === null) { lost++; response.fail(); } // outcome unknown to the client: the origin counter decides
        else if (r.status === 200) { ok++; response.add(d.now() - t); }
        else if (r.status === 503 && r.label === 'gateway-busy') { busy++; response.fail(); }
        else { other++; response.fail(); }
      }
    }));
    const redeemElapsed = d.now() - redeemStart;
    const clean = other === 0 && ok > 0 && !signal.aborted;
    return {
      status: clean ? 'PASS' : 'FAIL', expected: 'accepted',
      counters: { observations: wires.length, issuance_successes: wires.length, claims_successful: ok, queue_rejected: busy, transport_failures: lost, requests_rejected: other },
      failure_labels: clean ? [] : ['assertion-failed'],
      measurements: [acquisition.summary('token_acquisition_ms', mintElapsed), response.summary('protected_response_ms', redeemElapsed)],
    };
  } finally { for (const w of wires) w.fill(0); }
}
export const performance_ = (ctx: ScenarioContext): Promise<ScenarioOutcome> => performanceWith(ctx);
