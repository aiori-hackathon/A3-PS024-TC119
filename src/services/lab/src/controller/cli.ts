// `lab` command line (plan section 9.1). One supervised foreground command owns a run:
//   lab preflight                 read-only checks of the host, Compose file and provisioned secrets
//   lab run [--per-client N] [--partial] [--scenarios a,b --out report.json]
//                                 confirm any old generation is gone, recreate roles (fresh incarnations), bootstrap the
//                                 replay store through the shared artifact, launch the gateway with its private input,
//                                 enable one run, supervise it, and close it through the strong reset barrier
//   lab fence                     emergency stop: strong FENCE (else kill-and-confirm) for every role, no run knowledge needed
//   lab verify-report --file F    schema, evidence-rule and privacy check of a report file ([--require-pass])
// Output is fixed single-line JSON with ids and states only. No token, voucher, key, password or reply body is printed.
//
// Ownership rules this file enforces:
//  * A new controller never recreates or flushes anything until the previous generation is CONFIRMED gone by container
//    identity. Acquiring the lock proves nothing about that.
//  * The lock file is released only when shutdown was confirmed (or nothing was ever created). Otherwise it stays, and the
//    next controller must fence and confirm before doing anything.
//  * Every container created is recorded in an outer cleanup scope before it is used, so a failure at ANY point, including
//    before a run exists, is cleaned up by immutable identity.
// `--partial` is a development mode without the gateway. It uses a partial reset barrier that refuses eight-role runs and it
// never reports a complete suite as PASS; a full run uses the real ResetBarrier.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PROTOCOL } from '../../../../contracts/lib/index.ts';
import { ResetBarrier, type ResetTarget } from '../../../../security/reset-barrier.ts';
import { CLIENT_IDS, type ClientId, type ResetPort, type RoleLink, type RoleName } from './ports.ts';
import { DockerAdapters, DockerProject, ROLE_NAMES, SERVICE_FOR_ROLE, realDocker, type Instance, type Target } from './docker.ts';
import { LabRun, ControllerError, type RunLinks } from './run.ts';
import { PartialResetBarrier } from './partial-barrier.ts';
import { acquireProjectLock, LockHeldError } from './lock.ts';
import { discovery, emergencyFence } from './envelope.ts';
import { LinkError } from './link.ts';
import { CleanupScope, ScopeBarrier, discardRedis, stopRoles } from './scope.ts';
import { DockerRedis, DockerRedisIo } from './redis-docker.ts';
import { DockerGatewayLauncher } from './gateway-docker.ts';
import { buildReport, writeReportAtomic } from '../report/build.ts';
import { verifyReportFile } from '../report/verify.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..');
const composeFile = join(root, 'infra', 'compose.yaml');
const secretsDir = join(root, '.runtime', 'secrets');
const say = (o: Record<string, unknown>) => process.stdout.write(JSON.stringify(o) + '\n');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const flag = (name: string) => process.argv.includes(name);
const option = (name: string, fallback: string) => { const i = process.argv.indexOf(name); return i < 0 ? fallback : process.argv[i + 1] ?? fallback; };
const ALL_ROLES: RoleName[] = ROLE_NAMES;
const SERVICES_FULL = ['issuer', 'protected-origin', 'client-a', 'client-b', 'client-c', 'client-d', 'client-e', 'redis', 'proxy', 'gateway'];

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
    ['docker daemon reachable', (await realDocker.run(['version', '--format', '{{.Server.Version}}'], { timeoutMs: 20_000 })).status === 0],
    ['compose file valid', (await project.compose(['config', '-q'], { timeoutMs: 30_000 })).status === 0],
    ['secrets provisioned (.runtime/secrets)', existsSync(join(secretsDir, 'client', 'ca.crt')) && existsSync(join(secretsDir, 'gateway', 'tls.key')) && existsSync(join(secretsDir, 'controller', 'redis-password'))],
    ['node major is 24', Number(process.versions.node.split('.')[0]) === 24],
  ];
  for (const [name, ok] of checks) say({ check: name, ok });
  return checks.every(([, ok]) => ok) ? 0 : 1;
}

async function fence(): Promise<number> {
  const project = new DockerProject(realDocker, composeFile);
  const adapters = new DockerAdapters(project, new Map());
  let failed = 0;
  for (const role of ALL_ROLES) {
    let instance: Instance;
    try { instance = await project.instance(role); } catch { say({ role, fenced: null, note: 'not present' }); continue; }
    const link = project.openLink(instance);
    let strong = false;
    try { const r = await link.send(emergencyFence('operator-stop'), 12_000); strong = r['ok'] === true && r['result'] === 'FENCED'; } catch { /* fall back to kill-and-confirm */ } finally { link.close(); }
    if (strong) { say({ role, fenced: true, method: 'fenced' }); continue; }
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 12_000);
    try { await adapters.terminate({ role, incarnation: '0'.repeat(32), instance_id: instance.container_id }, ctl.signal); say({ role, fenced: true, method: 'terminated' }); }
    catch { say({ role, fenced: false }); failed++; } finally { clearTimeout(t); }
  }
  return failed === 0 ? 0 : 1;
}

async function run(): Promise<number> {
  const partial = flag('--partial');
  const perClient = Number(option('--per-client', '2'));
  let lock;
  try { lock = acquireProjectLock(join(root, '.runtime', 'project.lock')); }
  catch (e) { if (e instanceof LockHeldError) { say({ error: 'project-lock-held' }); return 3; } throw e; }

  const project = new DockerProject(realDocker, composeFile);
  const scope = new CleanupScope();
  const links = new Map<RoleName, RoleLink>();
  const adapters = new DockerAdapters(project, links);
  let runRef: LabRun | null = null;
  let released = false;
  const releaseLock = () => { if (!released) { released = true; lock.release(); } };
  let confirmed = false; // true only when shutdown of everything this controller created was confirmed
  try {
    // 1. The previous generation must be confirmed gone, by immutable ID, before anything is recreated.
    const old = new CleanupScope();
    for (const e of await project.existing()) { if (e.service === 'redis') old.recordRedis(e.container_id); else if (e.service !== 'proxy') old.recordRole({ name: e.service, container_id: e.container_id }); }
    if (old.roles.length > 0 || old.redisId) {
      const oldAdapters = new DockerAdapters(project, new Map());
      if (!(await stopRoles(old, oldAdapters)) || !(await discardRedis(old, oldAdapters))) { say({ error: 'old-generation-unconfirmed' }); return 1; } // lock stays
    }

    // 2. Fresh containers. Record every identity before using it.
    const services = partial ? SERVICES_FULL.filter((s) => s !== 'gateway') : SERVICES_FULL;
    const up = await project.compose(['up', '-d', '--force-recreate', '--build', ...services], { timeoutMs: 900_000 });
    const roles: RoleName[] = partial ? ALL_ROLES.filter((r) => r !== 'gateway') : ALL_ROLES;
    const instances = new Map<RoleName, Instance>();
    for (const role of roles) { try { const i = await project.instance(role); instances.set(role, i); scope.recordRole({ name: SERVICE_FOR_ROLE[role], container_id: i.container_id, role }); } catch { /* recorded below if others exist */ } }
    let redisId: string | null = null;
    try { redisId = await project.redisInstance(); scope.recordRedis(redisId); } catch { /* handled below */ }
    if (up.status !== 0 || instances.size !== roles.length || !redisId) { say({ error: 'compose-up-failed' }); throw new Error('setup'); }

    for (const role of roles.filter((r) => r !== 'gateway')) { const link = await connect(project, instances.get(role)!); links.set(role, link); scope.recordLink(instances.get(role)!.container_id, link); }
    const runLinks: RunLinks = { issuer: links.get('issuer')!, origin: links.get('origin')!,
      clients: Object.fromEntries(CLIENT_IDS.map((c) => [c, links.get(`client-${c}` as RoleName)!])) as unknown as Record<ClientId, RoleLink> };

    // 3. Replay store (shared artifact) and gateway launcher (private stdin input).
    const io = new DockerRedisIo(realDocker, redisId, readFileSync(join(secretsDir, 'controller', 'redis-password'), 'utf8').trim());
    const redis = new DockerRedis(io);
    const baseLauncher = partial ? undefined : new DockerGatewayLauncher(realDocker, instances.get('gateway')!, { secretsDir });
    const launcher = baseLauncher && { async launch(input: Parameters<DockerGatewayLauncher['launch']>[0]) {
      const link = await baseLauncher.launch(input); links.set('gateway', link); scope.recordLink(instances.get('gateway')!.container_id, link); return link;
    } };

    // 4. Reset: the real barrier once a complete snapshot exists; identity-bound cleanup before that.
    let inner: ResetPort | null = null;
    const build = (): ResetPort => {
      if (inner) return inner;
      const found = runRef!.discovered, manifest = runRef!.manifestSoFar;
      if (partial) {
        const participants: Target[] = roles.map((role) => ({ role, incarnation: found[role] ?? '', instance_id: instances.get(role)!.container_id }));
        if (manifest && participants.every((p) => /^[0-9a-f]{32}$/.test(p.incarnation))) {
          return (inner = new PartialResetBarrier({ run_id: runRef!.runId!, config_digest: runRef!.configDigest!, redis_instance_id: redisId!, participants }, adapters));
        }
      } else if (manifest && ALL_ROLES.every((r) => /^[0-9a-f]{32}$/.test(found[r] ?? ''))) {
        const participants: ResetTarget[] = ALL_ROLES.map((role) => ({ role: role as ResetTarget['role'], incarnation: found[role]!, instance_id: instances.get(role)!.container_id }));
        const barrier = ResetBarrier.prepare({ manifest, redis_instance_id: redisId!, participants }, {
          fence: (t, req, s) => adapters.fence(t as Target, req, s), terminate: (t, s) => adapters.terminate(t as Target, s),
          reportOrigin: (t, req, s) => adapters.reportOrigin(t as Target, req, s), discardRedis: (id, s) => adapters.discardRedis(id, s),
        });
        return (inner = { fenceAll: () => barrier.fenceAll(), discardOldRedis: (r) => barrier.discardOldRedis(r as never) });
      }
      return (inner = new ScopeBarrier(scope, adapters)); // incomplete snapshot: never fabricate one
    };
    const reset: ResetPort = { fenceAll: () => build().fenceAll(), discardOldRedis: (r) => build().discardOldRedis(r) };

    runRef = new LabRun({ links: runLinks, redis, reset, ...(launcher ? { gatewayLauncher: launcher } : {}) }, { perClient, clientProfile: 'demo' });
    const stopWatching = project.watch([...instances.values()], (role) => runRef!.roleLost(role));
    const stop = () => void runRef!.stop('operator-stop');
    process.once('SIGINT', stop); process.once('SIGTERM', stop);

    const info = await runRef.start();
    say({ event: 'enabled', run_id: info.run_id, config_digest: info.config_digest, roles: Object.keys(info.incarnations).length });
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
      snapshot();
      const finalReport = verifyReportFile(out);
      say({ event: 'report', ok: finalReport.ok, status: finalReport.status });
    }
    const closed = await runRef.closed();
    stopWatching();
    confirmed = closed.reset_confirmed;
    say({ event: 'closed', reason: closed.reason, reset_confirmed: closed.reset_confirmed, origin_counts: adapters.originCounts });
    return closed.reset_confirmed ? 0 : 1;
  } catch (e) {
    say({ error: e instanceof ControllerError ? e.code : 'controller-failed', step: e instanceof ControllerError ? e.step : undefined });
    // Outer cleanup: close the run if there is one, otherwise (or if that is unconfirmed) clean up by recorded identity.
    if (runRef) { const r = await runRef.stop('unsafe-state'); confirmed = r.reset_confirmed; }
    if (!confirmed) confirmed = (await stopRoles(scope, adapters)) && (await discardRedis(scope, adapters));
    return 1;
  } finally {
    // Release ownership ONLY when shutdown of everything this controller created was confirmed (or nothing was created).
    if (confirmed || (scope.roles.length === 0 && !scope.redisId)) releaseLock();
    else say({ event: 'lock-retained', reason: 'shutdown-unconfirmed' });
  }
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
