// Client-side named scenarios that need no gateway: S03 voucher-policy against the real issuer, and S14 the client half
// of network-boundaries. Both are fixed allowlisted code: no caller-supplied URL, command, header or byte. Vouchers used
// here are the client's own inventory, spent by the check, and are never reported or retained.
import { connect } from 'node:net';
import { lookup } from 'node:dns';
import { randomBytes } from 'node:crypto';
import { epochAt, PROTOCOL } from '../../../../contracts/lib/index.ts';
import { LabIssuance, challengeFor, verifyTokenSignature } from '../protocol.ts';
import type { ScenarioContext, ScenarioOutcome } from './control.ts';

type Check = { name: string; ok: boolean };
const outcome = (checks: Check[], expected: string, extra: ScenarioOutcome['counters'] = {}): ScenarioOutcome => ({
  status: checks.every((c) => c.ok) ? 'PASS' : 'FAIL', expected,
  counters: { observations: checks.length, ...extra },
  failure_labels: checks.every((c) => c.ok) ? [] : ['assertion-failed'],
});

/**
 * S03: an unknown voucher is refused; a protocol-invalid request is refused WITHOUT spending the voucher; a legitimate
 * voucher authorizes exactly one signing and is not restored; a used voucher is refused.
 * The challenge is built locally: the issuer signs blinded inputs and cannot know or enforce the gateway's context.
 */
export async function voucherPolicy(ctx: ScenarioContext): Promise<ScenarioOutcome> {
  const a = ctx.takeVoucher(), b = ctx.takeVoucher();
  if (!a || !b) return { status: 'INCONCLUSIVE', expected: 'single-spend', failure_labels: ['missing-evidence'] };
  const spki = Buffer.from(ctx.manifest.token_key_spki_b64url, 'base64url');
  const epoch = epochAt(ctx.manifest, Date.now()).epoch;
  const fresh = () => LabIssuance.begin(challengeFor(ctx.manifest, epoch), spki);
  const checks: Check[] = [];
  const expect = (name: string, ok: boolean) => checks.push({ name, ok });

  const unknown = await fresh();
  expect('unknown voucher refused (403)', (await ctx.client.issuanceAttempt(unknown.requestWire, randomBytes(32))).status === 403);
  const none = await fresh();
  expect('request without a voucher refused (403)', (await ctx.client.issuanceAttempt(none.requestWire, null)).status === 403);

  // Protocol-invalid but complete: 422 and the voucher survives.
  const short = (await fresh()).requestWire.subarray(0, PROTOCOL.request_bytes - 1);
  expect('protocol-invalid request refused (422)', (await ctx.client.issuanceAttempt(short, b)).status === 422);
  const second = await fresh();
  const retry = await ctx.client.issuanceAttempt(second.requestWire, b);
  expect('the same voucher still signs after a 422 (not consumed)', retry.status === 200);
  if (retry.status === 200) {
    const token = await second.finalize(retry.body);
    expect('the signing is real: token finalizes and verifies publicly', await verifyTokenSignature(spki, token));
  }
  const reuseB = await fresh();
  expect('that voucher is spent after one signing (403)', (await ctx.client.issuanceAttempt(reuseB.requestWire, b)).status === 403);

  const first = await fresh();
  const used = await ctx.client.issuanceAttempt(first.requestWire, a);
  expect('another legitimate voucher signs once (200)', used.status === 200);
  const replay = await fresh();
  expect('and is not restored (403)', (await ctx.client.issuanceAttempt(replay.requestWire, a)).status === 403);
  a.fill(0); b.fill(0);
  return outcome(checks, 'single-spend', { issuance_successes: checks.filter((c) => c.name.includes('signs') && c.ok).length, issuance_failures: 5 });
}

// Lab topology addresses (infra/compose.yaml). The client must NOT be able to reach any of them directly.
export const LAB_DIRECT_TARGETS: readonly (readonly [string, number])[] = [
  ['172.28.50.10', 8080], ['172.28.40.10', 6379], ['172.28.20.10', 443], ['172.28.30.10', 443], ['1.1.1.1', 443],
];
export const LAB_UNRESOLVABLE = ['redis', 'protected-origin', 'issuer.lab.test', 'origin.lab.test'] as const;
export const DENIED_CONNECTS = [
  'issuer.lab.test:80', 'issuer.lab.test:8443', 'example.com:443', '172.28.20.10:443', '172.28.30.10:443', '172.28.40.10:6379', '172.28.50.10:8080',
  'redis:6379', 'protected-origin:8080', 'localhost:443', '127.0.0.1:443', 'issuer.lab.test.evil.example:443', 'evilissuer.lab.test:443',
] as const;

export type NetworkProbes = {
  tcp(host: string, port: number): Promise<boolean>;            // true when a connection is accepted
  resolves(name: string): Promise<boolean>;
  connectStatus(authority: string): Promise<number | null>;     // proxy reply code, null when none
};

export const realProbes = (proxy: { host: string; port: number }): NetworkProbes => ({
  tcp: (host, port) => new Promise((resolve) => {
    const s = connect({ host, port }); const done = (v: boolean) => { s.destroy(); resolve(v); };
    s.setTimeout(2000, () => done(false)); s.once('connect', () => done(true)); s.once('error', () => done(false));
  }),
  resolves: (name) => new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), 3000);
    lookup(name, (e) => { clearTimeout(timer); resolve(!e); });
  }),
  connectStatus: (authority) => new Promise((resolve) => {
    const s = connect(proxy); let head = '';
    const done = (v: number | null) => { s.destroy(); resolve(v); };
    s.setTimeout(4000, () => done(null)); s.once('error', () => done(null)); s.once('close', () => done(null));
    s.once('connect', () => s.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`));
    s.on('data', (d) => { head += d.toString('latin1'); const m = /^HTTP\/1\.[01] (\d{3})/.exec(head); if (m) done(Number(m[1])); });
  }),
});

/**
 * S14, client half: nothing but the proxy is reachable, names do not resolve, and the proxy refuses to tunnel anywhere
 * else. A positive control (the issuer tunnel) must succeed, otherwise "blocked" would prove nothing and the result is
 * INCONCLUSIVE. The independent half of the evidence is the origin's received counter, which must not move.
 */
export async function networkBoundariesWith(probes: NetworkProbes): Promise<ScenarioOutcome> {
  const control = await probes.connectStatus('issuer.lab.test:443');
  if (control !== 200) return { status: 'INCONCLUSIVE', expected: 'isolated', counters: { observations: 1 }, failure_labels: ['missing-evidence'] };
  const checks: Check[] = [];
  for (const [host, port] of LAB_DIRECT_TARGETS) checks.push({ name: `no direct path to ${host}:${port}`, ok: !(await probes.tcp(host, port)) });
  for (const name of LAB_UNRESOLVABLE) checks.push({ name: `${name} does not resolve`, ok: !(await probes.resolves(name)) });
  for (const authority of DENIED_CONNECTS) {
    const code = await probes.connectStatus(authority);
    checks.push({ name: `CONNECT ${authority} refused`, ok: code !== null && code !== 200 && code >= 400 });
  }
  const refused = checks.filter((c) => c.ok).length;
  return outcome(checks, 'isolated', { requests_rejected: refused });
}
export const networkBoundaries = (ctx: ScenarioContext): Promise<ScenarioOutcome> => networkBoundariesWith(realProbes(ctx.proxy));
