// Report assembly (plan section 9.2). Only fixed-schema aggregates go in: no token or voucher material, no addresses,
// no per-request timing. The shared validator is the gate: nothing is written unless validateReport accepts it, and
// "PASS" can only be produced when every required scenario ran with independent origin evidence.
import { spawnSync } from 'node:child_process';
import { cpus, platform, release, totalmem } from 'node:os';
import { renameSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { PROTOCOL, validateReport, hex } from '../../../../contracts/lib/index.ts';

export type Status = 'PASS' | 'FAIL' | 'INCONCLUSIVE';
export type SuiteKind = 'demo' | 'security' | 'benchmark';
export type Counters = Partial<Record<'verification_attempts' | 'claims_successful' | 'replays_rejected' | 'requests_rejected' | 'queue_rejected' | 'transport_failures'
  | 'protected_requests_received' | 'generation_mismatches' | 'resources_served' | 'issuance_successes' | 'issuance_failures' | 'observations', number>>;
export type ScenarioRecord = {
  scenario_id: string; status: Status; expected: string; counters: Counters; origin_counts_available: boolean;
  worker_verification_attempts: { worker_index: number; attempts: number }[]; failure_labels: string[];
};
export type RunRecord = {
  run_id: string; config_digest: string; token_key_id: string; gateway_profile: 'B0' | 'B1'; client_profile: 'demo' | 'security' | 'benchmark';
  origin_incarnation: string | null; scenario_results: ScenarioRecord[]; measurements: unknown[];
  state_transitions: { state: string; reason: string }[]; retention_checks: { check_id: string; status: Status }[];
};
export type Report = Record<string, unknown> & { overall_status: Status; runs: RunRecord[]; suite_kind: SuiteKind };

/** FAIL beats everything; PASS needs complete, available evidence; anything else is visibly INCONCLUSIVE. */
export function overallStatus(kind: SuiteKind, runs: readonly RunRecord[]): Status {
  const scenarios = runs.flatMap((r) => r.scenario_results);
  if (scenarios.some((s) => s.status === 'FAIL') || runs.some((r) => r.retention_checks.some((c) => c.status === 'FAIL'))) return 'FAIL';
  const seen = new Set(scenarios.map((s) => s.scenario_id));
  const complete = runs.length > 0 && PROTOCOL.suite_required_scenarios[kind].every((id) => seen.has(id));
  const allPass = scenarios.length > 0 && scenarios.every((s) => s.status === 'PASS' && s.origin_counts_available);
  const retentionOk = runs.every((r) => r.retention_checks.every((c) => c.status === 'PASS'));
  return complete && allPass && retentionOk ? 'PASS' : 'INCONCLUSIVE';
}

function git(args: string[]): string | null {
  const r = spawnSync('git', args, { encoding: 'utf8', shell: false, timeout: 10_000 });
  return r.status === 0 ? r.stdout.trim() : null;
}
function dockerVersion(): string {
  const r = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { encoding: 'utf8', shell: false, timeout: 20_000 });
  return r.status === 0 && r.stdout.trim() ? r.stdout.trim().slice(0, 64) : 'unavailable';
}

export function collectProvenance(imageDigests: readonly string[] = []) {
  const commit = git(['rev-parse', 'HEAD']);
  return {
    software: {
      git_commit: commit && /^[0-9a-f]{40}$/.test(commit) ? commit : '0'.repeat(40),
      dirty: (git(['status', '--porcelain']) ?? 'unknown') !== '',
      node_version: process.versions.node,
      dependencies: { privacypass: '0.9.0', blindrsa: '0.4.5' },
      image_digests: imageDigests.filter((d) => /^sha256:[0-9a-f]{64}$/.test(d)).slice(0, 16),
    },
    environment: {
      os: `${platform()} ${release()}`.slice(0, 128), cpu_model: (cpus()[0]?.model ?? 'unknown').trim().slice(0, 256),
      cpu_count: Math.max(1, Math.min(1024, cpus().length)), memory_limit_bytes: totalmem(), docker_version: dockerVersion(), topology: 'single-host-private',
    },
  };
}

export function buildReport(input: { kind: SuiteKind; runs: RunRecord[]; imageDigests?: readonly string[]; now?: Date }): Report {
  const report = {
    schema_version: 1, contract_version: PROTOCOL.contract_version, suite_kind: input.kind, suite_id: hex(randomBytes(16)),
    // One coarse suite creation time; never a per-request timestamp.
    created_at_utc: (input.now ?? new Date()).toISOString().replace(/\.\d+Z$/, 'Z'),
    ...collectProvenance(input.imageDigests),
    runs: input.runs, overall_status: overallStatus(input.kind, input.runs),
  } as Report;
  validateReport(report); // throws ContractError rather than ever producing an unsound document
  return report;
}

/** Atomic replacement: a viewer reading during a run sees the old or the new snapshot, never a torn file. */
export function writeReportAtomic(path: string, report: Report): void {
  validateReport(report);
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(report, null, 2) + '\n', { mode: 0o644 });
  renameSync(tmp, path);
}
