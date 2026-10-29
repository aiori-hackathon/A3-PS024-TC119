import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { PROTOCOL, hex } from '../../../contracts/lib/index.ts';
import { buildReport, overallStatus, writeReportAtomic, type RunRecord, type ScenarioRecord } from '../src/report/build.ts';
import { privacyProblems, verifyReportFile, verifyReportText } from '../src/report/verify.ts';

const scenario = (id: string, over: Partial<ScenarioRecord> = {}): ScenarioRecord => ({
  scenario_id: id, status: 'PASS', expected: 'accepted', counters: { protected_requests_received: 0 }, origin_counts_available: true,
  worker_verification_attempts: [], failure_labels: [], ...over,
});
const run = (ids: string[], over: Partial<RunRecord> = {}): RunRecord => ({
  run_id: hex(randomBytes(16)), config_digest: hex(randomBytes(32)), token_key_id: hex(randomBytes(32)), gateway_profile: 'B1', client_profile: 'demo',
  origin_incarnation: hex(randomBytes(16)), scenario_results: ids.map((i) => scenario(i)), measurements: [],
  state_transitions: [{ state: 'ENABLED', reason: 'enabled' }, { state: 'FENCED', reason: 'completed' }], retention_checks: [], ...over,
});
const required = PROTOCOL.suite_required_scenarios.demo;

test('PASS only when every required scenario ran, passed, and had independent origin evidence', () => {
  assert.equal(overallStatus('demo', [run([...required])]), 'PASS');
  assert.equal(overallStatus('demo', [run(required.slice(0, -1))]), 'INCONCLUSIVE', 'a missing required scenario is never PASS');
  assert.equal(overallStatus('demo', [run(['voucher-policy', 'network-boundaries'])]), 'INCONCLUSIVE', 'a partial suite is visibly incomplete');
  assert.equal(overallStatus('demo', []), 'INCONCLUSIVE');
  const noOrigin = run([...required]); noOrigin.scenario_results[0]!.origin_counts_available = false;
  assert.equal(overallStatus('demo', [noOrigin]), 'INCONCLUSIVE');
  const inconclusive = run([...required]); inconclusive.scenario_results[1]!.status = 'INCONCLUSIVE';
  assert.equal(overallStatus('demo', [inconclusive]), 'INCONCLUSIVE');
  const failed = run([...required]); failed.scenario_results[2]!.status = 'FAIL';
  assert.equal(overallStatus('demo', [failed]), 'FAIL', 'one failure outranks everything');
  const badRetention = run([...required], { retention_checks: [{ check_id: 'mounts', status: 'FAIL' }] });
  assert.equal(overallStatus('demo', [badRetention]), 'FAIL');
  const unsureRetention = run([...required], { retention_checks: [{ check_id: 'mounts', status: 'INCONCLUSIVE' }] });
  assert.equal(overallStatus('demo', [unsureRetention]), 'INCONCLUSIVE');
  assert.equal(overallStatus('benchmark', [run(['performance'])]), 'PASS');
});

test('buildReport yields a schema-valid document and refuses to build an unsound one', () => {
  const report = buildReport({ kind: 'demo', runs: [run(['voucher-policy'])] });
  assert.equal(report.overall_status, 'INCONCLUSIVE');
  assert.match(report['created_at_utc'] as string, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  assert.equal((report['software'] as any).dependencies.privacypass, '0.9.0');
  assert.equal((report['environment'] as any).topology, 'single-host-private');
  assert.throws(() => buildReport({ kind: 'demo', runs: [run(['voucher-policy'], { gateway_profile: 'B9' as never })] }));
  assert.throws(() => buildReport({ kind: 'demo', runs: [run(['not-a-scenario'])] }));
});

test('atomic write: the target is replaced whole and no temporary file is left behind', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ps024-report-'));
  const path = join(dir, 'out', 'live.json');
  const first = buildReport({ kind: 'demo', runs: [run(['voucher-policy'])] });
  writeReportAtomic(path, first);
  const second = buildReport({ kind: 'demo', runs: [run(['voucher-policy', 'network-boundaries'])] });
  writeReportAtomic(path, second);
  assert.equal(JSON.parse(readFileSync(path, 'utf8')).suite_id, second['suite_id']);
  assert.deepEqual(readdirSync(join(dir, 'out')), ['live.json']);
  assert.throws(() => writeReportAtomic(path, { ...second, overall_status: 'PASS' } as never), 'an INCONCLUSIVE suite cannot be written as PASS');
  assert.equal(JSON.parse(readFileSync(path, 'utf8')).suite_id, second['suite_id'], 'a rejected write leaves the previous snapshot intact');
});

test('verify-report accepts an honest report and reports its status, including INCONCLUSIVE', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ps024-verify-'));
  const path = join(dir, 'r.json');
  writeReportAtomic(path, buildReport({ kind: 'demo', runs: [run(['voucher-policy'])] }));
  const v = verifyReportFile(path);
  assert.deepEqual([v.ok, v.status, v.problems], [true, 'INCONCLUSIVE', []]);
  writeReportAtomic(path, buildReport({ kind: 'demo', runs: [run([...required])] }));
  assert.equal(verifyReportFile(path).status, 'PASS');
});

test('verify-report rejects malformed, oversized, unreadable and overclaiming files', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ps024-verify-'));
  const good = JSON.parse(JSON.stringify(buildReport({ kind: 'demo', runs: [run(['voucher-policy'])] })));
  assert.equal(verifyReportText('{not json').ok, false);
  assert.equal(verifyReportText(JSON.stringify({ ...good, overall_status: 'PASS' })).ok, false, 'PASS without the required scenarios');
  assert.equal(verifyReportText(JSON.stringify({ ...good, extra: 'x' })).ok, false, 'unknown fields');
  const noEvidence = JSON.parse(JSON.stringify(good)); noEvidence.runs[0].scenario_results[0].origin_counts_available = false;
  assert.equal(verifyReportText(JSON.stringify({ ...noEvidence, overall_status: 'PASS' })).ok, false);
  assert.equal(verifyReportFile(join(dir, 'missing.json')).ok, false);
  const big = join(dir, 'big.json'); writeFileSync(big, ' '.repeat(1024 * 1024 + 1));
  assert.deepEqual(verifyReportFile(big).problems, ['file larger than 1 MiB']);
});

test('privacy scan: token, voucher, key and address-shaped content is caught wherever it hides', () => {
  const base = JSON.parse(JSON.stringify(buildReport({ kind: 'demo', runs: [run(['voucher-policy'])] })));
  assert.deepEqual(privacyProblems(base), [], 'a clean report has no problems (ids in their own fields are fine)');
  const tweak = (path: (r: any) => void) => { const r = JSON.parse(JSON.stringify(base)); path(r); return verifyReportText(JSON.stringify(r)); };
  const voucherDigest = hex(randomBytes(32));
  const token43 = Buffer.from(randomBytes(32)).toString('base64url');
  for (const [name, mutate] of [
    ['voucher digest in cpu_model', (r: any) => { r.environment.cpu_model = voucherDigest; }],
    ['voucher in docker_version', (r: any) => { r.environment.docker_version = token43; }],
    ['IPv4 in cpu_model', (r: any) => { r.environment.cpu_model = 'host 172.28.10.11'; }],
    ['IPv6 in cpu_model', (r: any) => { r.environment.cpu_model = 'fe80:0:0:0:1:2:3:4'; }],
    ['PEM marker', (r: any) => { r.environment.cpu_model = ['-----BEGIN', 'PRIVATE', 'KEY-----'].join(' '); /* built at runtime so the repo secret scanner does not flag this test */ }],
    ['64-hex in node_version', (r: any) => { r.software.node_version = voucherDigest.slice(0, 40); r.environment.os = voucherDigest; }],
  ] as [string, (r: any) => void][]) {
    const v = tweak(mutate);
    assert.equal(v.ok, false, name);
    assert.ok(v.problems.length > 0, name);
  }
  // Ordinary environment strings that contain dots are not mistaken for addresses.
  assert.equal(tweak((r) => { r.environment.os = 'linux 6.6.87.2-microsoft-standard-WSL2'; r.environment.docker_version = '29.4.0'; }).ok, true);
});
