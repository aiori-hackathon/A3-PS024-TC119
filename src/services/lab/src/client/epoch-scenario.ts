// S09 epoch-boundary. Runs only in a plan that moved run_start_ms back (suites.ts `epochOffsetMs`) so the first 600 s boundary
// falls inside the run. A real, genuinely signed epoch-0 token is held across the boundary and must then be refused, while a
// token for the new epoch is accepted. A control token redeemed just before the boundary proves the old epoch was serviceable
// (otherwise "refused afterwards" would prove nothing). Credentials stay in local variables and are wiped before returning.
import type { ScenarioContext, ScenarioOutcome } from './control.ts';
import type { LabClient } from './client.ts';

const MAX_WAIT_MS = 150_000, POLL_MS = 1500;
export type EpochDeps = { sleep: (ms: number) => Promise<void>; now: () => number };
const real: EpochDeps = { sleep: (ms) => new Promise((r) => setTimeout(r, ms)), now: () => Date.now() };
const inconclusive = (label: string): ScenarioOutcome => ({ status: 'INCONCLUSIVE', expected: 'rejected', failure_labels: [label] });

/** Polls until the gateway offers an epoch greater than `from`, or the bounded wait or the abort signal ends it. */
async function waitForBoundary(client: LabClient, from: number, signal: AbortSignal, d: EpochDeps) {
  const deadline = d.now() + MAX_WAIT_MS;
  while (d.now() < deadline && !signal.aborted) {
    const parsed = await client.fetchChallenge().catch(() => null);
    if (parsed && parsed.epoch > from) return parsed;
    await d.sleep(POLL_MS);
  }
  return null;
}

export async function epochBoundaryWith(ctx: ScenarioContext, d: EpochDeps = real): Promise<ScenarioOutcome> {
  const { client } = ctx;
  if (!ctx.hasVoucher(3)) return inconclusive('missing-evidence');
  const before = await client.fetchChallenge();
  const wires: Uint8Array[] = [];
  try {
    const stale = await client.issueWire(before.challenge); wires.push(stale);   // held across the boundary, never presented before it
    const control = await client.issueWire(before.challenge); wires.push(control);
    const early = await client.redeemWire(control);
    const after = await waitForBoundary(client, before.epoch, ctx.signal, d);
    if (!after) return inconclusive('missing-evidence');                           // the boundary never arrived within the bound
    const late = await client.redeemWire(stale);
    const fresh = await client.issueWire(after.challenge); wires.push(fresh);
    const current = await client.redeemWire(fresh);
    const checks = [
      { name: 'the old epoch served a token before the boundary', ok: early.status === 200 },
      { name: 'a genuinely signed old-epoch token is refused after the boundary', ok: late.status === 401 && (late.label === 'token-expired' || late.label === 'token-context-mismatch') },
      { name: 'the new epoch is offered and its token accepted', ok: after.epoch === before.epoch + 1 && current.status === 200 },
    ];
    const ok = checks.every((c) => c.ok);
    return { status: ok ? 'PASS' : 'FAIL', expected: 'rejected',
      counters: { observations: checks.length, issuance_successes: 3, claims_successful: [early, current].filter((r) => r.status === 200).length, requests_rejected: late.status === 401 ? 1 : 0 },
      failure_labels: ok ? [] : ['assertion-failed'] };
  } finally { for (const w of wires) w.fill(0); }
}
export const epochBoundary = (ctx: ScenarioContext): Promise<ScenarioOutcome> => epochBoundaryWith(ctx);
