import test from 'node:test';
import assert from 'node:assert/strict';
import { auditRetention } from '../src/controller/retention.ts';
import type { DockerCli, RunResult } from '../src/controller/docker.ts';
import type { RedisIo } from '../../../contracts/lib/replay.ts';

const ok = (stdout = '', status = 0): RunResult => ({ status, stdout, stderr: '', timedOut: false, failed: false });
const good = () => ({
  HostConfig: { Tmpfs: { '/tmp': 'rw', '/run/ps024': 'rw' }, LogConfig: { Type: 'none' }, PortBindings: {}, Privileged: false, NetworkMode: 'x', PidMode: '', ReadonlyRootfs: true },
  Mounts: [{ Type: 'bind', Source: '/h/s', Destination: '/run/secrets/tls.crt', RW: false }],
});
const TARGETS = [{ service: 'issuer', container_id: 'a'.repeat(64) }, { service: 'proxy', container_id: 'b'.repeat(64) }, { service: 'redis', container_id: 'c'.repeat(64) }];

function world(over: { inspect?: (service: string) => unknown; files?: (id: string) => string; logs?: string; proxyConf?: string } = {}) {
  const byId = new Map(TARGETS.map((t) => [t.container_id, t.service]));
  const cli: DockerCli = {
    async run(args) {
      if (args[0] === 'inspect') { const svc = byId.get(args[1]!)!; return ok(JSON.stringify([over.inspect ? over.inspect(svc) : good()])); }
      if (args[0] === 'logs') return over.logs ? ok(over.logs) : { ...ok('', 1), stderr: 'configured logging driver does not support reading' };
      if (args[0] === 'exec' && args.includes('find')) return ok(over.files ? over.files(args[2]!) : '');
      if (args[0] === 'exec' && args.includes('cat')) return ok(over.proxyConf ?? 'Syslog Off\nListen 1.2.3.4\n# LogFile "/x"\n');
      return ok();
    },
    spawn() { throw new Error('unused'); },
  };
  const redis: Record<string, unknown> = { 'slowlog-max-len': '0', 'acllog-max-len': '0', 'latency-monitor-threshold': '0', 'notify-keyspace-events': '', appendonly: 'no', save: '' };
  const io: RedisIo = { call: async (c, ...a) => {
    if (c === 'CONFIG') return [a[1], redis[a[1] as string] ?? ''];
    if (c === 'SLOWLOG' || c === 'ACL' || c === 'LATENCY') return [];
    return null;
  } };
  return { cli, io, redis };
}
const audit = (w: ReturnType<typeof world>, problems: string[] | null = []) => auditRetention(w.cli, TARGETS, w.io, '/nonexistent-runtime', problems);
const status = (r: Awaited<ReturnType<typeof audit>>, id: string) => r.find((c) => c.check_id === id)?.status;

test('a clean deployment passes every check that can be evaluated; an absent runtime directory is INCONCLUSIVE, not PASS', async () => {
  const r = await audit(world());
  assert.deepEqual(r.map((c) => c.check_id), ['app-sinks', 'proxy-sinks', 'redis-diagnostics', 'mounts', 'runtime-files', 'report-allowlist', 'host-boundary']);
  for (const id of ['app-sinks', 'proxy-sinks', 'redis-diagnostics', 'mounts', 'report-allowlist', 'host-boundary']) assert.equal(status(r, id), 'PASS', id);
  assert.equal(status(r, 'runtime-files'), 'INCONCLUSIVE');
});

test('image-layer logs are not runtime history: only tmpfs (the writable areas) are searched', async () => {
  const seen: string[][] = [];
  const w = world({ files: () => '' });
  const real = w.cli.run.bind(w.cli);
  w.cli.run = async (args, o) => { if (args.includes('find')) seen.push(args.slice(args.indexOf('find') + 1)); return real(args, o); };
  await audit(w);
  assert.ok(seen.length > 0 && seen.every((a) => !a.includes('/var/log') && !a.includes('/run/secrets')), JSON.stringify(seen));
});

test('findings: every kind of retention surface is caught', async () => {
  const cases: [string, Parameters<typeof world>[0], string][] = [
    ['stored Docker logs', { inspect: () => ({ ...good(), HostConfig: { ...good().HostConfig, LogConfig: { Type: 'json-file' } } }) }, 'app-sinks'],
    ['readable container output', { logs: 'GET /resource' }, 'app-sinks'],
    ['a file left in a writable area', { files: (id) => (id.startsWith('a') ? '/tmp/requests.log' : '') }, 'app-sinks'],
    ['proxy logging on', { proxyConf: 'LogFile "/var/log/tinyproxy.log"\nSyslog On\n' }, 'proxy-sinks'],
    ['Docker socket mounted', { inspect: () => ({ ...good(), Mounts: [{ Type: 'bind', Source: '/var/run/docker.sock', Destination: '/var/run/docker.sock', RW: true }] }) }, 'mounts'],
    ['writable host bind', { inspect: () => ({ ...good(), Mounts: [{ Type: 'bind', Source: '/host/data', Destination: '/data', RW: true }] }) }, 'mounts'],
    ['anonymous volume (e.g. an image VOLUME directive)', { inspect: () => ({ ...good(), Mounts: [{ Type: 'volume', Source: '/var/lib/docker/volumes/x', Destination: '/data', RW: true }] }) }, 'mounts'],
    ['published port', { inspect: () => ({ ...good(), HostConfig: { ...good().HostConfig, PortBindings: { '443/tcp': [{ HostPort: '443' }] } } }) }, 'host-boundary'],
    ['privileged container', { inspect: () => ({ ...good(), HostConfig: { ...good().HostConfig, Privileged: true } }) }, 'host-boundary'],
    ['writable root filesystem', { inspect: () => ({ ...good(), HostConfig: { ...good().HostConfig, ReadonlyRootfs: false } }) }, 'host-boundary'],
  ];
  for (const [name, over, id] of cases) assert.equal(status(await audit(world(over)), id), 'FAIL', name);
});

test('Redis diagnostics: configuration OR retained content is a finding; an unreachable store is INCONCLUSIVE', async () => {
  const w = world(); w.redis['slowlog-max-len'] = '128';
  assert.equal(status(await audit(w), 'redis-diagnostics'), 'FAIL');
  const w2 = world(); w2.io.call = async (c, ...a) => (c === 'CONFIG' ? [a[1], (w2.redis[a[1] as string] ?? '')] : c === 'SLOWLOG' ? [['entry']] : []);
  assert.equal(status(await audit(w2), 'redis-diagnostics'), 'FAIL', 'a non-empty slow log is retention even if configuration looks right');
  const w3 = world(); w3.io.call = async () => { throw new Error('down'); };
  assert.equal(status(await audit(w3), 'redis-diagnostics'), 'INCONCLUSIVE');
});

test('inability to look is never a pass: failed inspection or listing is INCONCLUSIVE; report problems are a FAIL, an unbuilt report INCONCLUSIVE', async () => {
  const w = world({ inspect: () => null });
  const r = await audit(w);
  assert.equal(status(r, 'mounts'), 'INCONCLUSIVE'); assert.equal(status(r, 'host-boundary'), 'INCONCLUSIVE');
  const noList = world(); const real = noList.cli.run.bind(noList.cli);
  noList.cli.run = async (args, o) => (args.includes('find') ? ok('', 1) : real(args, o));
  assert.equal(status(await audit(noList), 'app-sinks'), 'INCONCLUSIVE');
  assert.equal(status(await audit(world(), ['environment.cpu_model: address-like value']), 'report-allowlist'), 'FAIL');
  assert.equal(status(await audit(world(), null), 'report-allowlist'), 'INCONCLUSIVE');
});
