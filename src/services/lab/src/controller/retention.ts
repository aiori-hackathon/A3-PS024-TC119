// S15 retention audit: looks at the RUNNING deployment, not at configuration text, and reports fixed check ids with
// PASS / FAIL / INCONCLUSIVE. It asks what could keep request, token, voucher or address history after the fact: Docker log
// sinks, application and proxy files, Redis diagnostics, mounts, files under the runtime directory, and the report itself.
// What it does NOT see is stated plainly in docs: host swap, VM snapshots and memory dumps are outside its reach, so
// `host-boundary` covers published ports, privileges and the Docker socket only.
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { DockerCli } from './docker.ts';
import type { RetentionCheck } from './ports.ts';
import type { RedisIo } from '../../../../contracts/lib/replay.ts';

export type RetentionTarget = { service: string; container_id: string };
type Inspect = {
  Config?: { Env?: string[] }; HostConfig?: { Tmpfs?: Record<string, string>; LogConfig?: { Type?: string }; PortBindings?: Record<string, unknown>; Privileged?: boolean; NetworkMode?: string; PidMode?: string; ReadonlyRootfs?: boolean };
  Mounts?: { Type?: string; Source?: string; Destination?: string; RW?: boolean }[];
};
type Status = RetentionCheck['status'];
const worst = (a: Status, b: Status): Status => (a === 'FAIL' || b === 'FAIL' ? 'FAIL' : a === 'INCONCLUSIVE' || b === 'INCONCLUSIVE' ? 'INCONCLUSIVE' : 'PASS');

/** Mounts a role may legitimately have: its own secret files and read-only configuration. Anything else is a finding. */
const ALLOWED_MOUNT = (m: NonNullable<Inspect['Mounts']>[number]): boolean => {
  const dest = m.Destination ?? '';
  if (/docker\.sock/.test(m.Source ?? '') || /docker\.sock/.test(dest)) return false;
  if (m.Type === 'tmpfs') return true;
  if (dest.startsWith('/run/secrets/')) return m.RW === false;
  return ['/etc/redis/redis.conf', '/etc/tinyproxy/tinyproxy.conf', '/etc/tinyproxy/filter'].includes(dest) && m.RW === false;
};

export async function auditRetention(cli: DockerCli, targets: RetentionTarget[], io: RedisIo | null, runtimeDir: string, reportProblems: string[] | null): Promise<RetentionCheck[]> {
  const run = (args: string[]) => cli.run(args, { timeoutMs: 20_000 });
  const inspected = new Map<string, Inspect | null>();
  for (const t of targets) {
    const r = await run(['inspect', t.container_id]);
    try { inspected.set(t.service, r.status === 0 ? (JSON.parse(r.stdout) as Inspect[])[0] ?? null : null); } catch { inspected.set(t.service, null); }
  }
  const each = (f: (service: string, i: Inspect) => boolean): Status => {
    let s: Status = 'PASS';
    for (const t of targets) { const i = inspected.get(t.service); s = worst(s, i == null ? 'INCONCLUSIVE' : f(t.service, i) ? 'PASS' : 'FAIL'); }
    return s;
  };
  /** The only places a read-only-root container can write are its tmpfs mounts; image layers (apt logs, faillog) are not runtime history. */
  const writable = (service: string): string[] => Object.keys(inspected.get(service)?.HostConfig?.Tmpfs ?? {}).filter((d) => !d.startsWith('/run/secrets'));
  const filesIn = async (t: RetentionTarget, dirs: string[]): Promise<string[] | null> => {
    if (dirs.length === 0) return [];
    const r = await run(['exec', t.container_id, 'find', ...dirs, '-type', 'f']);
    if (r.status !== 0 || r.timedOut) return null; // cannot look: not evidence of absence
    return r.stdout.split('\n').map((l) => l.trim()).filter(Boolean);
  };
  const out: RetentionCheck[] = [];

  // app-sinks: no Docker log driver that stores output, nothing readable through `docker logs`, no regular files in writable areas.
  let app: Status = each((_s, i) => i.HostConfig?.LogConfig?.Type === 'none');
  for (const t of targets.filter((x) => x.service !== 'proxy' && x.service !== 'redis')) {
    const logs = await run(['logs', t.container_id]);
    if (logs.status === 0 && (logs.stdout.trim() !== '' || logs.stderr.trim() !== '')) app = 'FAIL';
    const files = await filesIn(t, writable(t.service));
    app = worst(app, files === null ? 'INCONCLUSIVE' : files.length === 0 ? 'PASS' : 'FAIL');
  }
  out.push({ check_id: 'app-sinks', status: app });

  // proxy-sinks: the proxy has no stored log (Docker driver none, Syslog off, no LogFile, no files).
  const proxy = targets.find((t) => t.service === 'proxy');
  let proxyStatus: Status = 'INCONCLUSIVE';
  if (proxy) {
    proxyStatus = inspected.get('proxy')?.HostConfig?.LogConfig?.Type === 'none' ? 'PASS' : 'FAIL';
    const conf = await run(['exec', proxy.container_id, 'cat', '/etc/tinyproxy/tinyproxy.conf']);
    const active = conf.stdout.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
    proxyStatus = worst(proxyStatus, conf.status !== 0 ? 'INCONCLUSIVE' : active.includes('Syslog Off') && !active.some((l) => /^LogFile\b/i.test(l)) ? 'PASS' : 'FAIL');
    const files = await filesIn(proxy, writable('proxy'));
    proxyStatus = worst(proxyStatus, files === null ? 'INCONCLUSIVE' : files.filter((f) => !/tinyproxy\.pid$/.test(f)).length === 0 ? 'PASS' : 'FAIL');
  }
  out.push({ check_id: 'proxy-sinks', status: proxyStatus });

  // redis-diagnostics: slow log, ACL log, latency history and keyspace events are off AND empty.
  let redis: Status = 'INCONCLUSIVE';
  if (io) {
    try {
      const cfg = async (k: string) => { const r = await io.call('CONFIG', 'GET', k); return Array.isArray(r) ? String(r[1] ?? '') : r && typeof r === 'object' ? String((r as Record<string, unknown>)[k] ?? '') : ''; };
      const empty = async (...c: (string | number)[]) => { const r = await io.call(...(c as [string, ...(string | number)[]])); return Array.isArray(r) ? r.length === 0 : Number(r) === 0; };
      const ok = (await cfg('slowlog-max-len')) === '0' && (await cfg('acllog-max-len')) === '0' && (await cfg('latency-monitor-threshold')) === '0'
        && (await cfg('notify-keyspace-events')) === '' && (await cfg('appendonly')) === 'no' && (await cfg('save')) === ''
        && await empty('SLOWLOG', 'LEN') && await empty('ACL', 'LOG') && await empty('LATENCY', 'LATEST');
      redis = ok ? 'PASS' : 'FAIL';
    } catch { redis = 'INCONCLUSIVE'; }
  }
  out.push({ check_id: 'redis-diagnostics', status: redis });

  out.push({ check_id: 'mounts', status: each((_s, i) => (i.Mounts ?? []).every(ALLOWED_MOUNT)) });

  // runtime-files: the controller's runtime directory holds provisioned credentials and nothing that looks like captured traffic.
  let files: Status = 'INCONCLUSIVE';
  if (existsSync(runtimeDir)) {
    const names = readdirSync(runtimeDir).filter((n) => n !== 'project.lock' && !/\.json$/.test(n));
    files = names.every((n) => n === 'secrets') ? 'PASS' : 'FAIL';
    if (files === 'PASS' && existsSync(join(runtimeDir, 'secrets'))) {
      const dirs = readdirSync(join(runtimeDir, 'secrets'));
      files = dirs.every((d) => ['issuer', 'client', 'gateway', 'redis', 'controller'].includes(d)) ? 'PASS' : 'FAIL';
    }
  }
  out.push({ check_id: 'runtime-files', status: files });

  out.push({ check_id: 'report-allowlist', status: reportProblems === null ? 'INCONCLUSIVE' : reportProblems.length === 0 ? 'PASS' : 'FAIL' });

  // host-boundary: nothing published, no host network or PID namespace, no privilege, no Docker socket.
  out.push({ check_id: 'host-boundary', status: each((_s, i) => Object.keys(i.HostConfig?.PortBindings ?? {}).length === 0 && i.HostConfig?.Privileged === false
    && i.HostConfig?.NetworkMode !== 'host' && !i.HostConfig?.PidMode && (i.Mounts ?? []).every((m) => !/docker\.sock/.test(`${m.Source}${m.Destination}`)) && i.HostConfig?.ReadonlyRootfs === true) });
  return out;
}
