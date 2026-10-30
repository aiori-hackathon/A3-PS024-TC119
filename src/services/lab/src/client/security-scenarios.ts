// Gateway-facing named scenarios (S02, S04 to S08). Fixed, allowlisted harness code that runs inside a client container:
// no caller-supplied URL, header, byte or script ever reaches it. Credentials made here are real tokens from the real
// issuer, kept only in local variables for the duration of one scenario and never reported, logged or returned. The
// controller supplies the independent evidence (origin arrival deltas, per-worker verification deltas); a client PASS alone
// never proves a gateway or "no forwarding" claim.
import { randomBytes } from 'node:crypto';
import { TokenChallenge } from '@cloudflare/privacypass-ts';
import { PROTOCOL, encodeBase64Url, redemptionContext, type Manifest } from '../../../../contracts/lib/index.ts';
import { LabIssuance, LabIssuer } from '../protocol.ts';
import type { ScenarioContext, ScenarioOutcome } from './control.ts';
import type { LabClient } from './client.ts';

type Check = { name: string; ok: boolean };
const finish = (checks: Check[], expected: string, counters: NonNullable<ScenarioOutcome['counters']> = {}): ScenarioOutcome => {
  const ok = checks.every((c) => c.ok);
  return { status: ok ? 'PASS' : 'FAIL', expected, counters: { observations: checks.length, ...counters }, failure_labels: ok ? [] : ['assertion-failed'] };
};
const notTested = (expected: string): ScenarioOutcome => ({ status: 'INCONCLUSIVE', expected, failure_labels: ['missing-evidence'] });
const CRLF = '\r\n';
const AUTH = (wire: Uint8Array | string) => `Authorization: PrivateToken token="${typeof wire === 'string' ? wire : encodeBase64Url(wire)}"`;

/** A request the gateway should refuse; true if it did (a 4xx, or the connection was closed without an answer). */
const refused = (r: { status: number | null; closed: boolean }) => (r.status === null ? r.closed : r.status >= 400 && r.status < 500);

const rawRequest = (headers: string[], opts: { method?: string; path?: string; host?: string; body?: string } = {}): Buffer =>
  Buffer.from(`${opts.method ?? 'GET'} ${opts.path ?? '/resource'} HTTP/1.1${CRLF}Host: ${opts.host ?? PROTOCOL.origin_name}${CRLF}${headers.map((h) => h + CRLF).join('')}Connection: close${CRLF}${CRLF}${opts.body ?? ''}`, 'latin1');

/** Gateway still answers with a fresh, well-formed challenge: used as a positive control before and after an attack. */
async function alive(client: LabClient): Promise<boolean> { try { await client.fetchChallenge(); return true; } catch { return false; } }

/** S04: size, encoding, type, duplicate-parameter, header, body and framing abuse is refused and nothing is forwarded. */
export async function malformedToken(ctx: ScenarioContext): Promise<ScenarioOutcome> {
  const { client } = ctx;
  if (!(await alive(client))) return notTested('rejected');
  const good = randomBytes(PROTOCOL.token_bytes); good[0] = 0; good[1] = 2; // well-formed Type 2 length and type, garbage content
  const typed = (type: number, length = PROTOCOL.token_bytes) => { const b = randomBytes(length); b[0] = type >> 8; b[1] = type & 255; return b; };
  const cases: [string, Buffer][] = [
    ['353-byte token', rawRequest([AUTH(typed(2, 353))])],
    ['355-byte token', rawRequest([AUTH(typed(2, 355))])],
    ['empty token', rawRequest([AUTH('')])],
    ['4096-byte token', rawRequest([AUTH(typed(2, 4096))])],
    ['invalid base64url character (+)', rawRequest([AUTH(encodeBase64Url(good).replace(/^./, '+'))])],
    ['invalid base64url character (/)', rawRequest([AUTH(encodeBase64Url(good).replace(/^./, '/'))])],
    ['misplaced padding', rawRequest([AUTH(encodeBase64Url(good) + '=')])],
    ['whitespace inside the token', rawRequest([AUTH(encodeBase64Url(good).replace(/^.{10}/, (m) => m + ' '))])],
    ['unsupported token type 1', rawRequest([AUTH(typed(1))])],
    ['unsupported token type 0xda7a', rawRequest([AUTH(typed(0xda7a))])],
    ['duplicate token parameter', rawRequest([`Authorization: PrivateToken token="${encodeBase64Url(good)}", token="${encodeBase64Url(good)}"`])],
    ['duplicate Authorization header', rawRequest([AUTH(good), AUTH(good)])],
    ['wrong scheme', rawRequest([`Authorization: Bearer ${encodeBase64Url(good)}`])],
    ['oversized header value (9000 bytes)', rawRequest([`Authorization: PrivateToken token="${'A'.repeat(9000)}"`])],
    ['more than 32 headers', rawRequest([AUTH(good), ...Array.from({ length: 40 }, (_, i) => `X-Pad-${i}: 1`)])],
    ['GET with a body', rawRequest([AUTH(good), 'Content-Length: 5'], { body: 'hello' })],
    ['Transfer-Encoding: chunked', rawRequest([AUTH(good), 'Transfer-Encoding: chunked'], { body: '0\r\n\r\n' })],
    ['POST method', rawRequest([AUTH(good), 'Content-Length: 0'], { method: 'POST' })],
    ['wrong path', rawRequest([AUTH(good)], { path: '/other' })],
    ['query string', rawRequest([AUTH(good)], { path: '/resource?x=1' })],
    ['wrong authority', rawRequest([AUTH(good)], { host: 'evil.lab.test' })],
  ];
  const checks: Check[] = [];
  for (const [name, bytes] of cases) checks.push({ name, ok: refused(await client.rawGateway(bytes)) });
  checks.push({ name: 'gateway still serves a fresh challenge afterwards', ok: await alive(client) });
  return finish(checks, 'rejected', { requests_rejected: checks.filter((c) => c.ok).length - 1 });
}

const flip = (wire: Uint8Array, at: number, mask = 0x80): Uint8Array => { const b = Uint8Array.from(wire); b[at] = b[at]! ^ mask; return b; };
const REJECT_LABELS = new Set(['token-invalid', 'token-key-unknown', 'token-context-mismatch', 'token-malformed']);

/** S05: modified nonce/authenticator, random token and a REAL token under another key are all rejected, with no arrival. */
export async function signatureAndKey(ctx: ScenarioContext): Promise<ScenarioOutcome> {
  const { client } = ctx;
  if (!ctx.hasVoucher(1)) return notTested('rejected');
  const parsed = await client.fetchChallenge();
  const real = await client.issueWire(parsed.challenge); // genuinely signed, never presented unmodified
  const attacker = await LabIssuer.generate(PROTOCOL.issuer_name);
  const foreign = await LabIssuance.begin(parsed.challenge, attacker.publicKeySpki);
  const foreignWire = await foreign.finalize(await attacker.sign(foreign.requestWire)); // valid signature, wrong issuer key
  const random = randomBytes(PROTOCOL.token_bytes); random[0] = 0; random[1] = 2;
  const variants: [string, Uint8Array, Set<string>][] = [
    ['modified nonce', flip(real, 2), REJECT_LABELS],
    ['modified nonce (last byte)', flip(real, 33, 1), REJECT_LABELS],
    ['modified challenge digest', flip(real, 40), REJECT_LABELS],
    ['modified token key id', flip(real, 70), new Set(['token-key-unknown', 'token-invalid'])],
    ['modified authenticator (first byte)', flip(real, 98), REJECT_LABELS],
    ['modified authenticator (last byte)', flip(real, PROTOCOL.token_bytes - 1, 1), REJECT_LABELS],
    ['all-zero authenticator', Uint8Array.from([...real.subarray(0, 98), ...new Uint8Array(256)]), REJECT_LABELS],
    ['random token of the right type and length', random, REJECT_LABELS],
    ['valid signature under another issuer key', foreignWire, new Set(['token-key-unknown'])],
  ];
  const checks: Check[] = [];
  let rejected = 0;
  for (const [name, wire, labels] of variants) {
    const r = await client.redeemWire(wire);
    const ok = r.status === 401 && r.label !== null && labels.has(r.label) && r.wwwAuthenticate.length === 1;
    checks.push({ name, ok }); if (ok) rejected++;
  }
  real.fill(0); foreignWire.fill(0);
  return finish(checks, 'rejected', { requests_rejected: rejected, issuance_successes: 2 });
}

/** S06: genuinely signed tokens for another allowed-to-sign context are refused despite valid signatures. */
export async function wrongContext(ctx: ScenarioContext): Promise<ScenarioOutcome> {
  const { client, manifest } = ctx;
  if (!ctx.hasVoucher(2)) return notTested('rejected');
  const parsed = await client.fetchChallenge();
  const otherRun: Manifest = { ...manifest, run_id: 'ff'.repeat(16) };
  const contexts: [string, TokenChallenge][] = [
    ['next epoch context', new TokenChallenge(PROTOCOL.token_type, manifest.issuer_name, redemptionContext(manifest, parsed.epoch + 1), [manifest.origin_name])],
    ['another run id in the context', new TokenChallenge(PROTOCOL.token_type, manifest.issuer_name, redemptionContext(otherRun, parsed.epoch), [manifest.origin_name])],
  ];
  const checks: Check[] = []; let rejected = 0;
  for (const [name, challenge] of contexts) {
    const wire = await client.issueWire(challenge); // real signature from the real issuer over a different context
    const r = await client.redeemWire(wire);
    const ok = r.status === 401 && (r.label === 'token-context-mismatch' || r.label === 'token-expired');
    checks.push({ name, ok }); if (ok) rejected++;
    wire.fill(0);
  }
  return finish(checks, 'rejected', { requests_rejected: rejected, issuance_successes: 2 });
}

/** S07: first use reaches the origin once; the second is refused; the copy never causes a second arrival. */
export async function sequentialReplay(ctx: ScenarioContext): Promise<ScenarioOutcome> {
  const { client } = ctx;
  if (!ctx.hasVoucher(1)) return notTested('single-spend');
  const parsed = await client.fetchChallenge();
  const wire = await client.issueWire(parsed.challenge);
  const first = await client.redeemWire(wire);
  const second = await client.redeemWire(wire);
  const third = await client.redeemWire(wire);
  wire.fill(0);
  return finish([
    { name: 'first presentation accepted', ok: first.status === 200 },
    { name: 'second presentation refused as a replay', ok: second.status === 401 && second.label === 'token-already-redeemed' },
    { name: 'third presentation refused as a replay', ok: third.status === 401 && third.label === 'token-already-redeemed' },
  ], 'single-spend', { claims_successful: first.status === 200 ? 1 : 0, replays_rejected: [second, third].filter((r) => r.label === 'token-already-redeemed').length, issuance_successes: 1 });
}

/** S08: 20 simultaneous presentations of one token. Healthy trial: exactly one 200 and nineteen replays. Never more than one win. */
export async function concurrentReplay(ctx: ScenarioContext): Promise<ScenarioOutcome> {
  const { client } = ctx;
  const PRESENTATIONS = 20, MAX_TRIALS = 5, WANT_HEALTHY = 2;
  let healthy = 0, wins = 0, replays = 0, busy = 0, transport = 0, trials = 0, doubleSpend = false;
  while (trials < MAX_TRIALS && healthy < WANT_HEALTHY && ctx.hasVoucher(1)) {
    trials++;
    const parsed = await client.fetchChallenge();
    const wire = await client.issueWire(parsed.challenge);
    const results = await Promise.all(Array.from({ length: PRESENTATIONS }, () => client.redeemWire(wire).catch(() => ({ status: 0, label: null as string | null }))));
    wire.fill(0);
    const w = results.filter((r) => r.status === 200).length;
    const rp = results.filter((r) => r.status === 401 && r.label === 'token-already-redeemed').length;
    wins += w; replays += rp;
    busy += results.filter((r) => r.status === 503).length; transport += results.filter((r) => r.status === 0).length;
    if (w > 1) doubleSpend = true;
    if (w === 1 && rp === PRESENTATIONS - 1) healthy++; // only a fully admitted and evaluated subtrial earns the 19-replay assertion
  }
  const counters = { claims_successful: wins, replays_rejected: replays, queue_rejected: busy, transport_failures: transport, issuance_successes: trials, observations: trials * PRESENTATIONS };
  if (doubleSpend) return { status: 'FAIL', expected: 'single-spend', counters, failure_labels: ['assertion-failed'] };
  if (healthy === 0) return { status: 'INCONCLUSIVE', expected: 'single-spend', counters, failure_labels: ['overload'] }; // reported honestly, not retried forever
  return { status: 'PASS', expected: 'single-spend', counters, failure_labels: [] };
}

/** S02 (one client's part): two tokens through the shared proxy, both accepted once, a copy of one refused. */
export async function sharedEgress(ctx: ScenarioContext): Promise<ScenarioOutcome> {
  const { client } = ctx;
  if (!ctx.hasVoucher(2)) return notTested('accepted');
  const parsed = await client.fetchChallenge();
  const a = await client.issueWire(parsed.challenge), b = await client.issueWire(parsed.challenge);
  const copy = Uint8Array.from(a);
  const ra = await client.redeemWire(a), rb = await client.redeemWire(b), reuse = await client.redeemWire(copy);
  a.fill(0); b.fill(0); copy.fill(0);
  return finish([
    { name: 'first token accepted', ok: ra.status === 200 }, { name: 'second token accepted', ok: rb.status === 200 },
    { name: 'reuse of the first token refused', ok: reuse.status === 401 && reuse.label === 'token-already-redeemed' },
  ], 'accepted', { claims_successful: [ra, rb].filter((r) => r.status === 200).length, replays_rejected: reuse.label === 'token-already-redeemed' ? 1 : 0, issuance_successes: 2 });
}
