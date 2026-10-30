// Controller-orchestrated scenarios: the ones that need real faults or credentials that cross processes. The controller
// drives them through the security harness (one-shot processes inside client containers) and the fault port (real Redis
// and Docker faults). Nothing is simulated: a fault is applied to the live deployment and the gateway's answer, the
// origin's independent counters and the gateway's own status decide the result. Quarantined credentials live only in
// controller memory for the duration of the scenario (or, for S13, the Vault across one reset) and are zeroed afterwards.
import { PROTOCOL, type Manifest } from '../../../../contracts/lib/index.ts';
import type { FaultPort, HarnessPort, Json, RedisFault, Vault } from './ports.ts';

export type ScenarioData = { status: 'PASS' | 'FAIL' | 'INCONCLUSIVE'; expected: string; counters: Record<string, number>; failure_labels: string[];
  /** Names of the failed checks (fixed strings written in this file; never request, reply or credential content). For operator output only, not the report. */
  failed?: string[] };
export type OrchestrationContext = {
  manifest: Manifest; harness: HarnessPort | undefined; faults: FaultPort | undefined; vault: Vault;
  takeVouchers: (n: number) => string[] | null;
  gatewayStatus: () => Promise<Json | null>;
  /** The controller's own view: has supervision already closed this run, and why. A faulted gateway stops acknowledging heartbeats, so this is expected. */
  closing: () => { closing: boolean; reason: string | null };
  sleep: (ms: number) => Promise<void>;
};
export type Handler = (ctx: OrchestrationContext) => Promise<ScenarioData>;

type Check = { name: string; ok: boolean };
const done = (checks: Check[], expected: string, counters: Record<string, number> = {}): ScenarioData => {
  const ok = checks.every((c) => c.ok);
  return { status: ok ? 'PASS' : 'FAIL', expected, counters: { observations: checks.length, ...counters }, failure_labels: ok ? [] : ['assertion-failed'], failed: checks.filter((c) => !c.ok).map((c) => c.name) };
};
const notTested = (expected: string): ScenarioData => ({ status: 'INCONCLUSIVE', expected, counters: {}, failure_labels: ['missing-evidence'] });
const zero = (tokens: Uint8Array[]) => { for (const t of tokens) t.fill(0); };
const KEY_ID_AT = 66; // type(2) + nonce(32) + challenge digest(32), then the 32-byte token key id
const keyIdHex = (token: Uint8Array) => Buffer.from(token.subarray(KEY_ID_AT, KEY_ID_AT + 32)).toString('hex');

/** S16: a thief presenting a copied, unused bearer token first wins; the original holder then fails. The bearer-token limit. */
export const stolenUnusedToken: Handler = async (ctx) => {
  const v = ctx.takeVouchers(1);
  if (!ctx.harness || !v) return notTested('bearer-limit');
  const tokens = await ctx.harness.issue('A', ctx.manifest, v);
  try {
    const thief = (await ctx.harness.present('B', ctx.manifest, [tokens[0]!]))[0]!;   // a different client process, a copy of the bytes
    const holder = (await ctx.harness.present('A', ctx.manifest, [tokens[0]!]))[0]!;  // the legitimate holder, afterwards
    return done([
      { name: 'the thief, presenting first, is accepted', ok: thief.status === 200 },
      { name: 'the legitimate holder is then refused as a replay', ok: holder.status === 401 && holder.label === 'token-already-redeemed' },
    ], 'bearer-limit', { claims_successful: thief.status === 200 ? 1 : 0, replays_rejected: holder.label === 'token-already-redeemed' ? 1 : 0, issuance_successes: 1 });
  } finally { zero(tokens); }
};

/** S13, part 1 (in the OLD run): obtain one spent and one unused credential and quarantine them across the reset. Not a report row. */
export async function captureOldCredentials(ctx: OrchestrationContext): Promise<boolean> {
  const v = ctx.takeVouchers(2);
  if (!ctx.harness || !v) return false;
  const tokens = await ctx.harness.issue('A', ctx.manifest, v);
  const first = (await ctx.harness.present('B', ctx.manifest, [tokens[0]!]))[0]!; // spent in the old generation
  if (first.status !== 200) { zero(tokens); return false; }
  ctx.vault.put('old-run', tokens); zero(tokens);
  return true;
}

/** S13, part 2 (in the NEW run, after the previous generation was confirmed gone): old credentials fail, a fresh one works once. */
export const restartAndReset: Handler = async (ctx) => {
  const old = ctx.vault.take('old-run');
  const v = ctx.takeVouchers(1);
  if (!ctx.harness || !old || old.length !== 2 || !v) return notTested('recovered');
  try {
    const freshKey = ctx.manifest.token_key_id;
    const [spent, unused] = await ctx.harness.present('A', ctx.manifest, old);
    const [fresh] = await ctx.harness.issue('B', ctx.manifest, v);
    const accepted = (await ctx.harness.present('C', ctx.manifest, [fresh!]))[0]!;
    const reused = (await ctx.harness.present('C', ctx.manifest, [fresh!]))[0]!;
    zero([fresh!]);
    return done([
      { name: 'the old run used a different signing key', ok: keyIdHex(old[0]!) !== freshKey && keyIdHex(old[1]!) !== freshKey },
      { name: 'the old SPENT credential is refused (unknown key)', ok: spent!.status === 401 && spent!.label === 'token-key-unknown' },
      { name: 'the old UNUSED credential is refused (unknown key)', ok: unused!.status === 401 && unused!.label === 'token-key-unknown' },
      { name: 'a fresh credential is accepted once', ok: accepted.status === 200 },
      { name: 'and refused when reused', ok: reused.status === 401 && reused.label === 'token-already-redeemed' },
    ], 'recovered', { requests_rejected: 2, claims_successful: accepted.status === 200 ? 1 : 0, replays_rejected: reused.label === 'token-already-redeemed' ? 1 : 0, issuance_successes: 1 });
  } finally { zero(old); }
};

const closedLike = (s: Json | null): boolean => !!s && s['ok'] === true && (s['data']?.fault != null || s['data']?.run_closed === true || s['state'] !== 'ENABLED');

/**
 * S12 / S17: inject a real replay-store fault into the live deployment. Valid, unspent tokens issued BEFORE the fault must
 * not be accepted afterwards, the gateway must report itself closed, and reloading scripts must not revive it. The caller's
 * independent evidence is the origin's received counter, which must stay at zero.
 */
export const redisFault = (kind: RedisFault, expected: string): Handler => async (ctx) => {
  const v = ctx.takeVouchers(2);
  if (!ctx.harness || !ctx.faults || !v) return notTested(expected);
  const tokens = await ctx.harness.issue('A', ctx.manifest, v);
  try {
    const before = await ctx.gatewayStatus();
    await ctx.faults.redis(kind);
    // After the fault the gateway must fail CLOSED. Either it answers "unavailable" (503) or, because an unexpected store state
    // closes the whole run, it drops the connection without authorizing anything. Both are acceptable; what is not acceptable is
    // any acceptance of a valid, unspent token, or any arrival at the origin (checked independently by the controller).
    const attempt = (client: 'A' | 'B' | 'C', token: Uint8Array) =>
      ctx.harness!.present(client, ctx.manifest, [token]).then((r) => r[0]!, () => ({ status: 0, label: null as string | null }));
    const first = await attempt('B', tokens[0]!);
    await ctx.sleep(300);
    const second = await attempt('C', tokens[1]!);
    if (kind !== 'redis-stop') await ctx.faults.reloadScripts().catch(() => undefined); // an attempted "live repair"
    const third = await attempt('B', tokens[0]!);
    // Give supervision its bounded chance to notice; the closure must come from the gateway's own failure signal.
    for (let i = 0; i < 40 && !ctx.closing().closing; i++) await ctx.sleep(250);
    const after = await ctx.gatewayStatus();
    const unavailable = (r: { status: number; label: string | null }) => r.status === 503 && r.label === 'authorization-unavailable';
    const never200 = (r: { status: number }) => r.status !== 200;
    const closing = ctx.closing();
    return done([
      { name: 'the gateway was serving before the fault', ok: !!before && before['ok'] === true && before['state'] === 'ENABLED' },
      { name: `a valid unspent token is NOT accepted after the fault [observed ${first.status}/${first.label}]`, ok: never200(first) },
      { name: 'a second valid token is not accepted either', ok: never200(second) },
      { name: 'reloading scripts or state does not revive the run', ok: never200(third) },
      { name: 'the run closed because the gateway failed (supervision lost), or the gateway reports itself closed', ok: closedLike(after) || (closing.closing && closing.reason === 'control-lost') },
    ], expected, { requests_rejected: [first, second, third].filter(unavailable).length, transport_failures: [first, second, third].filter((r) => r.status === 0).length, issuance_successes: 2 });
  } finally { zero(tokens); }
};

/** S11: the origin hangs after the claim. The claim stays spent, nothing is retried, and the failure is bounded. */
export const upstreamFailure: Handler = async (ctx) => {
  const v = ctx.takeVouchers(1);
  if (!ctx.harness || !ctx.faults || !v) return notTested('fail-closed');
  const [token] = await ctx.harness.issue('A', ctx.manifest, v);
  try {
    await ctx.faults.pauseOrigin();
    let first: { status: number; label: string | null }, elapsed: number;
    try { const t0 = performance.now(); first = (await ctx.harness.present('B', ctx.manifest, [token!]))[0]!; elapsed = performance.now() - t0; }
    finally { await ctx.faults.unpauseOrigin(); }
    await ctx.sleep(500); // let the paused origin drain whatever it buffered
    const again = (await ctx.harness.present('C', ctx.manifest, [token!]))[0]!;
    const bound = PROTOCOL.gateway_common.origin_timeout_ms + PROTOCOL.gateway_common.request_timeout_ms;
    return done([
      { name: 'the stalled origin yields 502/504, not a success', ok: first.status === 502 || first.status === 504 },
      { name: 'the failure is bounded by the origin and request deadlines', ok: elapsed <= bound },
      { name: 'the claim stays spent: the same token is a replay afterwards, never retried or refunded', ok: again.status === 401 && again.label === 'token-already-redeemed' },
    ], 'fail-closed', { transport_failures: 1, replays_rejected: again.label === 'token-already-redeemed' ? 1 : 0, issuance_successes: 1 });
  } finally { zero([token!]); }
};

export const ORCHESTRATED: Record<string, Handler> = {
  'stolen-unused-token': stolenUnusedToken,
  'restart-and-reset': restartAndReset,
  'upstream-failure': upstreamFailure,
};
export const REDIS_FAULT_SCENARIOS: Record<string, { kind: RedisFault; id: 'redis-failure' | 'clock-rollback'; expected: string }> = {
  'redis-failure:script-flush': { kind: 'script-flush', id: 'redis-failure', expected: 'fail-closed' },
  'redis-failure:clock-delete': { kind: 'clock-delete', id: 'redis-failure', expected: 'fail-closed' },
  'redis-failure:policy-corrupt': { kind: 'policy-corrupt', id: 'redis-failure', expected: 'fail-closed' },
  'redis-failure:redis-stop': { kind: 'redis-stop', id: 'redis-failure', expected: 'fail-closed' },
  'clock-rollback:clock-regress': { kind: 'clock-regress', id: 'clock-rollback', expected: 'observed-clock-regression' },
};
for (const [key, f] of Object.entries(REDIS_FAULT_SCENARIOS)) ORCHESTRATED[key] = redisFault(f.kind, f.expected);
