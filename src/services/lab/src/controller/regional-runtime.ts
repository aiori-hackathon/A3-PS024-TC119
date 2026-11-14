import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ChildProcess } from 'node:child_process';
import { canonicalJson, configurationDigest, PROTOCOL, type Manifest } from '../../../../contracts/lib/index.ts';
import { REGIONAL, regionalPolicyDigest, validateRegionalPolicy, type RegionalPolicy, type RegionalProfile } from '../../../../contracts/lib/regional.ts';
import { decodeCanonicalRegionalJson, validateArcBootstrap, type ArcBootstrap } from '../../../../contracts/lib/regional-wire.ts';
import { ResetBarrier, type ResetTarget } from '../../../../security/reset-barrier.ts';
import { CLIENT_IDS, type ClientId, type Json, type RoleLink, type RoleName, type ResetPort } from './ports.ts';
import { DockerProject, DockerAdapters, ROLE_NAMES, SERVICE_FOR_ROLE, realDocker, type Instance } from './docker.ts';
import { DockerRedis, DockerRedisIo } from './redis-docker.ts';
import { DockerGatewayLauncher } from './gateway-docker.ts';
import { CleanupScope, ScopeBarrier, stopRoles, discardRedis } from './scope.ts';
import { LabRun, type RegionalRunHooks } from './run.ts';
import { discovery, newId, request } from './envelope.ts';
import { acquireProjectLock, type ProjectLock } from './lock.ts';

const wait = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
const SERVICES = ['issuer', 'protected-origin', 'client-a', 'client-b', 'client-c', 'client-d', 'client-e', 'redis', 'proxy', 'gateway'];
type Counts = { protected_requests_received: number; generation_mismatches: number; resources_served: number };

/** One outstanding private process command, with terminal uncertainty and bounded output. */
class ArcProcess {
  readonly #child: ChildProcess;
  #pending: { resolve: (value: Json) => void; reject: () => void; timer: NodeJS.Timeout } | null = null;
  #buffer = Buffer.alloc(0);
  #dead = false;
  constructor(container: string) {
    this.#child = realDocker.spawn(['exec', '-i', container, '/usr/local/bin/arc-service']);
    this.#child.stderr?.resume();
    this.#child.on('error', () => this.#fail());
    this.#child.on('close', () => this.#fail());
    this.#child.stdin?.on('error', () => this.#fail());
    this.#child.stdout?.on('data', (chunk: Buffer) => {
      if (this.#buffer.length + chunk.length > 65536) { this.#fail(); return; }
      this.#buffer = Buffer.concat([this.#buffer, chunk]);
      const end = this.#buffer.indexOf(10);
      if (end < 0) return;
      if (!this.#pending || end !== this.#buffer.length - 1) { this.#fail(); return; }
      try {
        const value = decodeCanonicalRegionalJson(this.#buffer, true) as Json;
        const pending = this.#pending;
        this.#pending = null;
        this.#buffer = Buffer.alloc(0);
        clearTimeout(pending.timer);
        pending.resolve(value);
      } catch { this.#fail(); }
    });
  }
  #fail(): void {
    this.#dead = true;
    if (this.#pending) {
      clearTimeout(this.#pending.timer);
      this.#pending.reject();
      this.#pending = null;
    }
    this.#child.stdin?.destroy();
  }
  call(value: Json, timeout = 1500): Promise<Json> {
    if (this.#dead || this.#pending) return Promise.reject(Error('arc-control-unavailable'));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.#fail(), timeout);
      this.#pending = { resolve, reject: () => reject(Error('arc-control-unavailable')), timer };
      this.#child.stdin!.write(canonicalJson(value) + '\n');
    });
  }
  close(): void { this.#child.stdin?.end(); }
}

export class RegionalLab {
  readonly #root: string;
  readonly #project: DockerProject;
  #run: LabRun | null = null;
  #scope: CleanupScope | null = null;
  #adapters: DockerAdapters | null = null;
  #lock: ProjectLock | null = null;
  #links = new Map<RoleName, RoleLink>();
  #instances = new Map<RoleName, Instance>();
  #arc: ArcProcess | null = null;
  #arcId: string | null = null;
  #stopWatching: (() => void) | null = null;
  #stopGateway: (() => void) | null = null;
  #built = false;
  #sourceRevision = '';
  #revision = 0;
  #busy = false;
  #closing: Promise<void> | null = null;
  #state = 'idle';
  #profile: RegionalProfile | null = null;
  #estimates = new Map<ClientId, number | null>();
  #counts: Counts | null = null;
  #evidenceState = 'incomplete';
  #originObservedAt: string | null = null;
  #enumerationUncertain = false;
  #windowTimer: NodeJS.Timeout | null = null;
  #comparison: Json[] = [];
  #theft: Json | null = null;
  constructor(root: string) {
    this.#root = root;
    this.#project = new DockerProject(realDocker, join(root, 'infra', 'compose.yaml'));
  }
  async prepare(): Promise<void> { await this.#build(); }
  status(): Json {
    const policy = this.#run?.info?.regional_policy;
    return {
      mode: 'live', observedAt: new Date().toISOString(), state: this.#state, profile: this.#profile, revision: this.#revision,
      ...(this.#run?.info ? { runId: this.#run.info.run_id } : {}),
      ...(policy ? { window: { label: 'Server-defined 60-second window', endsAt: new Date(policy.window_end_ms).toISOString() } } : {}),
      clients: CLIENT_IDS.map(clientId => ({ clientId, estimatedUsesLeft: this.#estimates.get(clientId) ?? null,
        state: this.#run?.phase === 'enabled' ? 'ready' : 'idle' })),
      evidence: { observedAt: this.#originObservedAt, state: this.#evidenceState,
        requestsReceived: this.#counts?.protected_requests_received ?? null,
        resourcesServed: this.#counts?.resources_served ?? null,
        generationMismatches: this.#counts?.generation_mismatches ?? null },
      comparison: this.#comparison,
      ...(this.#theft ? { theftScene: this.#theft } : {}),
    };
  }
  async execute(command: Json): Promise<Json> {
    if (this.#busy) throw Error('operation-in-progress');
    if (command.action !== 'start_run' && command.revision !== this.#revision) throw Error('stale-run');
    this.#busy = true;
    try {
      if (command.action === 'start_run') {
        if (!['ip', 'type2-bearer', 'arc', 'type2-holder'].includes(command.profile) || this.#run) throw Error('run-already-active');
        await this.#start(command.profile);
        return { outcome: 'started', status: this.status() };
      }
      if (command.action === 'reset_run') {
        await this.close();
        return { outcome: 'reset', status: this.status() };
      }
      if (command.action === 'run_comparison') return await this.#compare();
      if (command.action === 'run_theft_scene') return await this.#theftScene();
      if (!['acquire', 'access'].includes(command.action) || !CLIENT_IDS.includes(command.clientId)) throw Error('command-invalid');
      const result = await this.#action(command.clientId, command.action);
      return { ...result, status: this.status() };
    } catch {
      this.#state = 'uncertain';
      await this.close();
      return { outcome: 'uncertain', message: 'Operation interrupted. Allowance may already be consumed.', status: this.status() };
    } finally { this.#busy = false; }
  }
  async #build(): Promise<void> {
    if (this.#built) return;
    const revision = await this.#shell('git', ['log', '-1', '--format=%H', '--', 'src/services/arc']);
    this.#sourceRevision = revision.trim();
    if (!/^[0-9a-f]{40}$/.test(this.#sourceRevision)) throw Error('source-revision');
    if ((await this.#shell('git', ['status', '--porcelain', '--', 'src/services/arc'])).trim()) throw Error('uncommitted-arc-source');
    await this.#shell('git', ['diff', '--exit-code', this.#sourceRevision, '--', 'src/services/arc']);
    await this.#shell('docker', ['build', '--build-arg', `TF_ARC_SOURCE_REVISION=${this.#sourceRevision}`, '-f', 'src/services/arc/Dockerfile', '-t', 'tokenforge-arc:local', '.'], 900000);
    await this.#shell('docker', ['build', '--target', 'regional', '-f', 'src/services/lab/Dockerfile', '-t', 'tokenforge-lab:local', '.'], 300000);
    const built = await this.#project.compose(['build', 'gateway', 'proxy'], { timeoutMs: 300000 });
    if (built.status !== 0) throw Error('image-build');
    this.#built = true;
  }
  async #shell(command: string, args: string[], timeout = 30000): Promise<string> {
    // Asynchronous tools keep live lease supervision responsive.
    const { spawn } = await import('node:child_process');
    return new Promise((resolve, reject) => {
      const child = spawn(command, args, { cwd: this.#root, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
      let output = '';
      const timer = setTimeout(() => { child.kill(); reject(Error('tool-timeout')); }, timeout);
      child.stderr.resume();
      child.stdout.on('data', chunk => { if (output.length < 65536) output += chunk; });
      child.on('error', () => { clearTimeout(timer); reject(Error('tool-failed')); });
      child.on('close', code => { clearTimeout(timer); code === 0 ? resolve(output) : reject(Error('tool-failed')); });
    });
  }
  async #private(role: RoleName, value: Json): Promise<Json> {
    const id = newId();
    const input = canonicalJson({ ...value, request_id: id }) + '\n';
    const result = await realDocker.run(['exec', '-i', this.#instances.get(role)!.container_id, 'node', '/app/dist/regional-helper.mjs'], { input, timeoutMs: 30000 });
    if (result.status !== 0 || result.failed || result.timedOut) throw Error('regional-control-unavailable');
    const reply = decodeCanonicalRegionalJson(Buffer.from(result.stdout), true) as Json;
    if (reply.request_id !== id || reply.ok !== true) throw Error('regional-control-refused');
    return reply.data;
  }
  async #connect(instance: Instance): Promise<RoleLink> {
    for (let attempt = 0; attempt < 40; attempt++) {
      const link = this.#project.openLink(instance);
      try { if ((await link.send(discovery(), 2000)).ok === true) return link; } catch { /* startup read-only probe */ }
      link.close();
      await wait(150);
    }
    throw Error('role-control-unavailable');
  }
  async #start(profile: RegionalProfile): Promise<void> {
    this.#state = 'starting';
    this.#lock ??= acquireProjectLock(join(this.#root, '.runtime', 'project.lock'));
    this.#revision++;
    this.#profile = profile;
    this.#estimates.clear();
    this.#counts = null;
    this.#originObservedAt = null;
    this.#evidenceState = 'incomplete';
    await this.#build();
    const old = this.#scope = new CleanupScope();
    const oldAdapters = this.#adapters = new DockerAdapters(this.#project, new Map());
    await this.#reconcile(old);
    if (!(await stopRoles(old, oldAdapters)) || !(await discardRedis(old, oldAdapters))) throw Error('old-generation-unconfirmed');
    const scope = this.#scope = new CleanupScope();
    this.#links = new Map();
    this.#instances = new Map();
    const adapters = this.#adapters = new DockerAdapters(this.#project, this.#links);
    const up = await this.#project.compose(['up', '-d', '--no-build', '--force-recreate', ...SERVICES, ...(profile === 'arc' ? ['arc'] : [])], { timeoutMs: 120000 });
    await this.#reconcile(scope);
    for (const role of ROLE_NAMES) {
      try { const instance = await this.#project.instance(role); this.#instances.set(role, instance); scope.recordRole({ name: SERVICE_FOR_ROLE[role], role, container_id: instance.container_id }); } catch { /* record partial setup */ }
    }
    const redisId = await this.#project.redisInstance();
    scope.recordRedis(redisId);
    if (profile === 'arc') { this.#arcId = await this.#project.arcInstance(); scope.recordRole({ name: 'arc', container_id: this.#arcId }); }
    if (up.status !== 0 || this.#instances.size !== ROLE_NAMES.length) throw Error('compose-start-failed');
    for (const role of ROLE_NAMES.filter(role => role !== 'gateway')) {
      const link = await this.#connect(this.#instances.get(role)!);
      this.#links.set(role, link);
      scope.recordLink(this.#instances.get(role)!.container_id, link);
    }
    const io = new DockerRedisIo(realDocker, redisId, readFileSync(join(this.#root, '.runtime', 'secrets', 'controller', 'redis-password'), 'utf8').trim());
    const launcher = new DockerGatewayLauncher(realDocker, this.#instances.get('gateway')!, { secretsDir: join(this.#root, '.runtime', 'secrets') });
    this.#stopGateway = () => launcher.stop();
    const hooks = this.#hooks(profile);
    let barrier: ResetPort | null = null;
    const reset: ResetPort = {
      fenceAll: async () => {
        this.#arc?.close();
        if (this.#arcId) {
          await adapters.terminate({ role: 'issuer', incarnation: '0'.repeat(32), instance_id: this.#arcId }, AbortSignal.timeout(12000));
        }
        if (!barrier) {
          const manifest = this.#run?.manifestSoFar;
          const found = this.#run?.discovered ?? {};
          if (manifest && ROLE_NAMES.every(role => /^[0-9a-f]{32}$/.test(found[role] ?? ''))) {
            const prepared = ResetBarrier.prepare({ manifest, redis_instance_id: redisId,
              participants: ROLE_NAMES.map(role => ({ role: role as ResetTarget['role'], incarnation: found[role]!, instance_id: this.#instances.get(role)!.container_id })) }, adapters);
            barrier = { fenceAll: () => prepared.fenceAll(), discardOldRedis: receipt => prepared.discardOldRedis(receipt as never) };
          } else barrier = new ScopeBarrier(scope, adapters);
        }
        return barrier.fenceAll();
      },
      discardOldRedis: receipt => barrier!.discardOldRedis(receipt),
    };
    this.#run = new LabRun({ links: { issuer: this.#links.get('issuer')!, origin: this.#links.get('origin')!,
      clients: Object.fromEntries(CLIENT_IDS.map(id => [id, this.#links.get(`client-${id}`)!])) as Record<ClientId, RoleLink> },
      redis: new DockerRedis(io), reset, regional: hooks,
      gatewayLauncher: { launch: async input => {
        const link = await launcher.launch(input);
        this.#links.set('gateway', link);
        scope.recordLink(this.#instances.get('gateway')!.container_id, link);
        return link;
      } } }, { perClient: 1, gatewayProfile: 'B1', clientProfile: 'demo' });
    const watched = [...this.#instances.values(), ...(this.#arcId ? [{ role: 'issuer' as const, container_id: this.#arcId }] : [])];
    this.#stopWatching = this.#project.watch(watched, role => this.#run?.roleLost(role));
    await this.#run.start();
    void this.#run.closed().then(() => { if (this.#state === 'active') this.#state = 'error'; });
    this.#counts = await this.#origin();
    this.#state = 'active';
    this.#windowTimer = setTimeout(() => { void this.close().catch(() => { this.#state = 'error'; }); },
      Math.max(0, this.#run.info!.regional_policy!.window_end_ms - Date.now()));
  }
  async #reconcile(scope: CleanupScope): Promise<void> {
    this.#enumerationUncertain = true;
    for (const item of await this.#project.existing()) {
      if (item.service === 'redis') scope.recordRedis(item.container_id);
      else if (item.service !== 'proxy') scope.recordRole({ name: item.service, container_id: item.container_id });
    }
    this.#enumerationUncertain = false;
  }
  #hooks(profile: RegionalProfile): RegionalRunHooks {
    const issueKey = randomBytes(32).toString('hex');
    const verifyKey = randomBytes(32).toString('hex');
    const contextKey = randomBytes(32).toString('hex');
    const nonceKey = randomBytes(32).toString('hex');
    const sourceKey = randomBytes(32).toString('hex');
    let bootstrap: ArcBootstrap | null = null;
    let sequence = 0;
    const renew = (operation: string) => this.#arc!.call({ operation, lease_sequence: sequence++, lease_expires_ms: Date.now() + PROTOCOL.gateway_common.controller_lease_ms - 250 });
    return {
      bootstrap: async runId => {
        if (profile !== 'arc') return;
        this.#arc = new ArcProcess(this.#arcId!);
        const value = await this.#arc.call({ operation: 'bootstrap', run_id: runId, implementation_revision: this.#sourceRevision,
          issue_listen: '172.28.60.10:7101', verify_listen: '172.28.60.10:7102', issue_key: issueKey, verify_key: verifyKey }, 5000);
        bootstrap = validateArcBootstrap(value, { run_id: runId, arc_implementation_revision: this.#sourceRevision });
      },
      policy: manifest => validateRegionalPolicy({ contract_version: REGIONAL.contract_version, schema_version: 1,
        run_id: manifest.run_id, baseline_config_digest: configurationDigest(manifest), profile,
        window_start_ms: manifest.run_start_ms, window_end_ms: manifest.run_start_ms + REGIONAL.window_ms,
        quota: REGIONAL.quota, admitted_entitlements: REGIONAL.admitted_entitlements,
        resource_id: REGIONAL.resource_id, method: REGIONAL.method, url: REGIONAL.url,
        type2_key_id: ['type2-bearer', 'type2-holder'].includes(profile) ? manifest.token_key_id : null,
        arc_key_id: bootstrap?.arc_key_id ?? null, arc_implementation_revision: bootstrap?.arc_implementation_revision ?? null,
        arc_tag_encoding: bootstrap ? REGIONAL.arc_tag_encoding : null }, manifest),
      install: async policy => {
        if (this.#arc && (await this.#arc.call({ operation: 'install-policy', policy })).status !== 'installed') throw Error('arc-policy-refused');
      },
      gatewayStartup: policy => ({ policy, auth: profile === 'arc'
        ? { profile, bootstrap, endpoint: { host: '172.28.60.10', port: 7102 }, verify_key: verifyKey }
        : profile === 'type2-holder' ? { profile, context_key: contextKey, nonce_key: nonceKey }
        : profile === 'ip' ? { profile, source_key: sourceKey } : { profile } }),
      prepareRoles: async policy => {
        await this.#private('issuer', { operation: 'install', config: { policy,
          ...(bootstrap ? { arc: { bootstrap, endpoint: { host: '172.28.60.10', port: 7101 }, issueKey } } : {}) } });
        await Promise.all(CLIENT_IDS.map(id => this.#private(`client-${id}`, { operation: 'install', config: { policy,
          ...(profile === 'arc' ? { arcHelperPath: '/usr/local/bin/arc-client-helper' } : {}) } })));
      },
      enable: async () => { if (this.#arc && (await renew('enable')).status !== 'enabled') throw Error('arc-enable-refused'); },
      supervise: onFault => {
        if (!this.#arc) return () => {};
        let stopped = false;
        let timer: NodeJS.Timeout;
        const loop = async () => {
          if (stopped) return;
          try { if ((await renew('heartbeat')).status !== 'renewed') throw Error(); }
          catch { if (!stopped) onFault(); return; }
          if (!stopped) timer = setTimeout(loop, PROTOCOL.gateway_common.controller_heartbeat_ms);
        };
        timer = setTimeout(loop, PROTOCOL.gateway_common.controller_heartbeat_ms);
        return () => { stopped = true; clearTimeout(timer); };
      },
    };
  }
  async #origin(): Promise<Counts | null> {
    const info = this.#run?.info;
    if (!info) return null;
    try {
      const reply = await this.#links.get('origin')!.send(request('REPORT', { runId: info.run_id, digest: info.config_digest, incarnation: info.incarnations.origin! }));
      if (reply.ok !== true || reply.run_id !== info.run_id || reply.config_digest !== info.config_digest
        || reply.incarnation !== info.incarnations.origin || reply.data.origin_counts_available !== true) return null;
      const counts = reply.data.counters;
      const values = [counts.protected_requests_received, counts.generation_mismatches, counts.resources_served];
      if (values.some(value => !Number.isSafeInteger(value) || value < 0)) return null;
      this.#originObservedAt = new Date().toISOString();
      return { protected_requests_received: values[0], generation_mismatches: values[1], resources_served: values[2] };
    } catch { return null; }
  }
  async #action(clientId: ClientId, action: string, count = 1): Promise<Json> {
    if (this.#run?.phase !== 'enabled') throw Error('run-inactive');
    const before = await this.#origin();
    const value = await this.#private(`client-${clientId}`, { operation: 'action', action, count });
    this.#estimates.set(clientId, value.estimated_remaining);
    const results = value.results ?? [];
    const uncertain = results.some((result: Json) => result.delivery === 'uncertain') || value.error === 'regional-operation-failed';
    if (uncertain) this.#estimates.set(clientId, null);
    const after = this.#counts = await this.#origin();
    const accepted = results.filter((result: Json) => result.status === 200 && result.delivery === 'confirmed').length;
    const denied = results.filter((result: Json) => result.status >= 400 && result.delivery === 'confirmed').length;
    const arrivals = before && after ? after.protected_requests_received - before.protected_requests_received : null;
    const incomplete = uncertain || !!value.error || (action !== 'acquire' && results.length === 0);
    this.#evidenceState = arrivals === null || incomplete ? 'incomplete' : arrivals === accepted && after!.generation_mismatches === 0 ? 'verified' : 'mismatch';
    const first = results[0];
    return { outcome: uncertain ? 'uncertain' : accepted ? 'delivered' : action === 'acquire' && !value.error ? 'acquired' : 'refused',
      message: uncertain ? 'Delivery uncertain. The use may already be consumed.' : value.error ? 'Allowance unavailable or exhausted.' : undefined,
      ...(first?.status === 200 && first.resource_b64url ? { authorizedAccess: { clientId, text: Buffer.from(first.resource_b64url, 'base64url').toString('utf8') } } : {}),
      accepted, denied, attempts: results.length, originArrivals: arrivals, measurements: value.measurements,
      evidenceState: this.#evidenceState };
  }
  async #compare(): Promise<Json> {
    await this.close();
    this.#comparison = [];
    for (const profile of ['ip', 'type2-bearer', 'arc'] as const) {
      await this.#start(profile);
      const phases: Json[] = [];
      if (profile !== 'ip') for (const id of CLIENT_IDS) phases.push(await this.#action(id, 'acquire'));
      const abuser = await this.#action('A', 'abuse', 26);
      phases.push(abuser);
      const measurements = new Map<ClientId, Json>([['A', abuser.measurements ?? {}]]);
      let honest = 0;
      let denied = abuser.denied;
      for (const id of CLIENT_IDS.filter(id => id !== 'A')) for (let i = 0; i < REGIONAL.quota; i++) {
        const result = await this.#action(id, 'access');
        phases.push(result);
        measurements.set(id, result.measurements ?? {});
        honest += result.accepted;
        denied += result.denied;
      }
      const expectedHonest = profile === 'ip' ? 0 : 20;
      const arrivals = this.#counts?.protected_requests_received ?? null;
      const incomplete = phases.some(phase => phase.evidenceState === 'incomplete');
      const mismatch = phases.some(phase => phase.evidenceState === 'mismatch');
      const workloadMatches = honest === expectedHonest && arrivals === 25 && abuser.accepted === (profile === 'ip' ? 25 : 5)
        && abuser.attempts === 26 && abuser.denied === (profile === 'ip' ? 1 : 21) && !mismatch;
      const policy = this.#run!.info!.regional_policy!;
      const sum = (field: string) => [...measurements.values()].reduce((total, value) => total + (value[field] ?? 0), 0);
      this.#comparison.push({ profile, runId: policy.run_id, policyDigest: regionalPolicyDigest(policy),
        state: incomplete || arrivals === null ? 'INCONCLUSIVE' : workloadMatches ? 'PASS' : 'FAIL',
        accepted: abuser.accepted + honest, honestDelivered: honest, denied, originArrivals: arrivals,
        issuanceBytes: sum('issuance_request_bytes') + sum('issuance_response_bytes'), issuanceInteractions: sum('issuance_interactions'),
        preparationInteractions: sum('preparation_interactions'), latencyMs: Math.ceil(sum('redemption_ms') / 46) });
      await this.close();
    }
    return { outcome: 'comparison-complete', status: this.status() };
  }
  async #theftScene(): Promise<Json> {
    await this.close();
    await this.#start('type2-holder');
    const acquisition = await this.#action('A', 'acquire');
    const attack = await this.#action('A', 'attack');
    const owner = await this.#action('A', 'access');
    const race = await this.#action('A', 'race', 20);
    const phases = [acquisition, attack, owner, race];
    const incomplete = phases.some(result => result.evidenceState === 'incomplete');
    const mismatch = phases.some(result => result.evidenceState === 'mismatch');
    this.#theft = { state: incomplete ? 'INCONCLUSIVE' : attack.accepted === 0 && attack.denied === 1 && attack.originArrivals === 0
      && owner.accepted === 1 && owner.originArrivals === 1 && race.accepted === 1 && race.originArrivals === 1 && !mismatch ? 'PASS' : 'FAIL',
      raceScope: 'Concurrent duplicate requests',
      holderOutcome: owner.outcome, attackOriginArrivals: attack.originArrivals, ownerOriginArrivals: owner.originArrivals,
      raceOriginArrivals: race.originArrivals };
    await this.close();
    return { outcome: 'theft-complete', status: this.status() };
  }
  close(): Promise<void> {
    if (this.#closing) return this.#closing;
    const pending = this.#close();
    this.#closing = pending;
    void pending.finally(() => { if (this.#closing === pending) this.#closing = null; }).catch(() => {});
    return pending;
  }
  async #close(): Promise<void> {
    this.#state = 'resetting';
    if (this.#windowTimer) clearTimeout(this.#windowTimer);
    this.#windowTimer = null;
    this.#stopWatching?.();
    this.#stopWatching = null;
    let confirmed = true;
    if (this.#enumerationUncertain && this.#scope) {
      try { await this.#reconcile(this.#scope); } catch { this.#state = 'error'; throw Error('shutdown-unconfirmed'); }
    }
    if (this.#run) confirmed = (await this.#run.stop()).reset_confirmed;
    if (this.#scope && this.#adapters && !confirmed) confirmed = (await stopRoles(this.#scope, this.#adapters)) && (await discardRedis(this.#scope, this.#adapters));
    if (!this.#run && this.#scope && this.#adapters) confirmed = (await stopRoles(this.#scope, this.#adapters)) && (await discardRedis(this.#scope, this.#adapters));
    this.#arc?.close();
    this.#arc = null;
    if (!confirmed) { this.#state = 'error'; throw Error('shutdown-unconfirmed'); }
    this.#stopGateway?.();
    this.#stopGateway = null;
    this.#run = null;
    this.#scope = null;
    this.#arcId = null;
    this.#links.clear();
    this.#instances.clear();
    this.#estimates.clear();
    this.#lock?.release();
    this.#lock = null;
    this.#revision++;
    this.#state = 'idle';
    this.#profile = null;
  }
}
