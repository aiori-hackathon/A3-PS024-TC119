// `lab` command line (plan section 9.1). One supervised foreground command owns a run:
//   lab preflight                 read-only checks of the host, Compose file and provisioned secrets
//   lab run [--per-client N] [--no-gateway] [--dev-redis] [--scenarios a,b --out report.json]
//                                 recreate roles (fresh incarnations), build and enable one run, supervise until stopped
//   lab fence                     emergency stop: strong FENCE to every reachable role, no run knowledge needed
//   lab verify-report --file F    schema, evidence-rule and privacy check of a report file ([--require-pass])
// Output is fixed single-line JSON with ids and states only. No token, voucher, key, password or reply body is printed.
// `serve-report` belongs to the viewer work (M06) and is not implemented here.
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CLIENT_IDS, type ClientId, type RedisPort, type ResetPort, type RoleLink, type RoleName } from './ports.ts';
import { DockerAdapters, DockerProject, ROLE_NAMES, realDocker, type Instance, type Target } from './docker.ts';
import { LabRun, ControllerError, type RunLinks } from './run.ts';
import { PartialResetBarrier } from './partial-barrier.ts';
import { acquireProjectLock, LockHeldError } from './lock.ts';
import { discovery, emergencyFence } from './envelope.ts';
import { LinkError } from './link.ts';
import { PROTOCOL } from '../../../../contracts/lib/index.ts';
import { buildReport, writeReportAtomic } from '../report/build.ts';
import { verifyReportFile } from '../report/verify.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..');
const composeFile = join(root, 'infra', 'compose.yaml');
const say = (o: Record<string, unknown>) => process.stdout.write(JSON.stringify(o) + '\n');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const flag = (name: string) => process.argv.includes(name);
const option = (name: string, fallback: string) => { const i = process.argv.indexOf(name); return i < 0 ? fallback : process.argv[i + 1] ?? fallback; };

/** Opens a helper link, retrying while the role's control socket does not exist yet. */
async function connect(project: DockerProject, instance: Instance): Promise<RoleLink> {
  for (let attempt = 0; attempt < 50; attempt++) {
    const link = project.openLink(instance);
    try { const r = await link.send(discovery(), 3000); if (r['ok'] === true) return link; } catch (e) { if (!(e instanceof LinkError)) throw e; }
    link.close();
    await sleep(300);
  }
  throw new Error('role-unreachable');
}

async function preflight(): Promise<number> {
  const project = new DockerProject(realDocker, composeFile);
  const checks: [string, boolean][] = [
    ['docker daemon reachable', realDocker.run(['version', '--format', '{{.Server.Version}}']).status === 0],
    ['compose file valid', project.compose(['config', '-q']).status === 0],
    ['secrets provisioned (.runtime/secrets)', existsSync(join(root, '.runtime', 'secrets', 'client', 'ca.crt'))],
    ['node major is 24', Number(process.versions.node.split('.')[0]) === 24],
  ];
  for (const [name, ok] of checks) say({ check: name, ok });
  return checks.every(([, ok]) => ok) ? 0 : 1;
}

async function fence(): Promise<number> {
  const project = new DockerProject(realDocker, composeFile);
  let failed = 0;
  for (const role of ROLE_NAMES) {
    let instance: Instance;
    try { instance = project.instance(role); } catch { say({ role, fenced: null, note: 'not running' }); continue; }
    const link = project.openLink(instance);
    try {
      const r = await link.send(emergencyFence('operator-stop'), 12_000);
      const strong = r['ok'] === true && r['result'] === 'FENCED';
      say({ role, fenced: strong }); if (!strong) failed++;
    } catch { say({ role, fenced: false }); failed++; } finally { link.close(); }
  }
  // An unacknowledged role must be killed and confirmed by the operator; this command never claims a clean stop.
  return failed === 0 ? 0 : 1;
}

/** Development replay-store stand-in until Krish's bootstrap artifact exists (request 002). Never selected implicitly. */
const devRedis: RedisPort = {
  async prepare() { return { run_start_ms: Date.now(), snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40) }; },
  async install() { return { username: 'gateway', password: 'dev-placeholder' }; },
};

async function run(): Promise<number> {
  const noGateway = flag('--no-gateway');
  if (!noGateway) { say({ error: 'gateway-integration-unavailable', detail: 'run with --no-gateway until the gateway entry point and Redis bootstrap artifact are merged' }); return 2; }
  if (!flag('--dev-redis')) { say({ error: 'redis-bootstrap-unavailable', detail: 'pass --dev-redis to use the development stand-in' }); return 2; }
  const perClient = Number(option('--per-client', '2'));
  let lock;
  try { lock = acquireProjectLock(join(root, '.runtime', 'project.lock')); }
  catch (e) { if (e instanceof LockHeldError) { say({ error: 'project-lock-held' }); return 3; } throw e; }
  const project = new DockerProject(realDocker, composeFile);
  const roles: RoleName[] = ROLE_NAMES.filter((r) => r !== 'gateway');
  try {
    const up = project.compose(['up', '-d', '--force-recreate', '--build', 'issuer', 'protected-origin', 'client-a', 'client-b', 'client-c', 'client-d', 'client-e', 'redis', 'proxy'], 600_000);
    if (up.status !== 0) { say({ error: 'compose-up-failed' }); return 1; }
    const instances = new Map<RoleName, Instance>(roles.map((r) => [r, project.instance(r)]));
    const redisId = project.redisInstance();
    const links = new Map<RoleName, RoleLink>();
    for (const role of roles) links.set(role, await connect(project, instances.get(role)!));
    const adapters = new DockerAdapters(project, links);
    let runRef: LabRun | null = null;
    const reset: ResetPort = {
      async fenceAll() { return partial().fenceAll(); },
      async discardOldRedis(receipt) { return partial().discardOldRedis(receipt); },
    };
    let barrier: PartialResetBarrier | null = null;
    const partial = (): PartialResetBarrier => {
      if (barrier) return barrier;
      const found = runRef!.discovered;
      const participants: Target[] = roles.map((role) => {
        const inc = found[role]; if (!inc) throw new Error('incarnation-unknown');
        return { role, incarnation: inc, instance_id: instances.get(role)!.container_id };
      });
      return (barrier = new PartialResetBarrier({ run_id: runRef!.runId ?? '0'.repeat(32), config_digest: runRef!.configDigest ?? '0'.repeat(64), redis_instance_id: redisId, participants }, adapters));
    };
    const runLinks: RunLinks = { issuer: links.get('issuer')!, origin: links.get('origin')!,
      clients: Object.fromEntries(CLIENT_IDS.map((c) => [c, links.get(`client-${c}` as RoleName)!])) as unknown as Record<ClientId, RoleLink> };
    runRef = new LabRun({ links: runLinks, redis: devRedis, reset }, { perClient, clientProfile: 'demo' });
    const stopWatching = project.watch([...instances.values()], (role) => runRef!.roleLost(role));
    const stop = () => void runRef!.stop('operator-stop');
    process.once('SIGINT', stop); process.once('SIGTERM', stop);
    const info = await runRef.start();
    say({ event: 'enabled', run_id: info.run_id, config_digest: info.config_digest, roles: Object.keys(info.incarnations).length });
    // Optional named scenarios (fixed allowlist), one per client in order, with a live report snapshot after each.
    const wanted = option('--scenarios', '').split(',').filter(Boolean);
    const out = option('--out', '');
    if (wanted.length > 0) {
      if (wanted.some((id) => !(PROTOCOL.scenario_ids as readonly string[]).includes(id)) || !out) { await runRef.stop('operator-stop'); say({ error: 'bad-scenario-arguments' }); return 2; }
      const snapshot = () => { const rec = runRef!.runRecord(); if (rec) writeReportAtomic(out, buildReport({ kind: 'demo', runs: [rec] })); };
      for (const [i, id] of wanted.entries()) {
        const rec = await runRef.runScenario(CLIENT_IDS[i % CLIENT_IDS.length]!, id);
        say({ event: 'scenario', scenario_id: id, status: rec.status, origin_counts_available: rec.origin_counts_available });
        snapshot();
      }
      await runRef.stop('completed');
      snapshot(); // final snapshot includes the closing transitions
      const finalReport = verifyReportFile(out);
      say({ event: 'report', ok: finalReport.ok, status: finalReport.status });
    }
    const closed = await runRef.closed();
    stopWatching();
    say({ event: 'closed', reason: closed.reason, reset_confirmed: closed.reset_confirmed, origin_counts: adapters.originCounts });
    return closed.reset_confirmed ? 0 : 1;
  } catch (e) {
    say({ error: e instanceof ControllerError ? e.code : 'controller-failed', step: e instanceof ControllerError ? e.step : undefined });
    return 1;
  } finally { lock.release(); }
}

function verify(): number {
  const file = option('--file', '');
  if (!file) { say({ error: 'usage', detail: 'verify-report --file <path> [--require-pass]' }); return 2; }
  const v = verifyReportFile(file);
  say({ ok: v.ok, status: v.status, problems: v.problems });
  return v.ok && (!flag('--require-pass') || v.status === 'PASS') ? 0 : 1;
}

const command = process.argv[2];
const code = command === 'preflight' ? await preflight() : command === 'run' ? await run() : command === 'fence' ? await fence() : command === 'verify-report' ? verify()
  : (say({ error: 'usage', commands: ['preflight', 'run', 'fence', 'verify-report'] }), 2);
process.exit(code);
