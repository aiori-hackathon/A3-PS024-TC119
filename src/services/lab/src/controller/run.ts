// The foreground run controller (plan sections 5.2 to 5.5, 9.1). It holds no state that survives the process: it
// discovers fresh role incarnations, builds one run in the exact startup order, supervises it with sequenced heartbeats
// (one outstanding per link), and on ANY unsafe event closes through the strong reset barrier. It never retries a
// mutation, never replenishes vouchers, and never reopens a closed run. Failure to confirm shutdown leaves it closed.
import {
  PROTOCOL, makeManifest, configurationDigest, encodeBase64Url, decodeBase64Url, type Manifest, type ClientProfile, type GatewayProfile,
} from '../../../../contracts/lib/index.ts';
import { CLIENT_IDS, Vault, type RetentionCheck, type RetentionPort, type ClientId, type FaultPort, type GatewayLauncher, type HarnessPort, type Json, type RedisPort, type ResetPort, type RoleLink } from './ports.ts';
import { discovery, newId, request, type Target } from './envelope.ts';
import { batches, generateCohort } from './cohort.ts';
import type { RunRecord, ScenarioRecord } from '../report/build.ts';
import { ORCHESTRATED, REDIS_FAULT_SCENARIOS, captureOldCredentials, type OrchestrationContext, type ScenarioData } from './orchestrated.ts';

export type ControllerErrorCode =
  | 'discovery-failed' | 'role-not-fresh' | 'setup-failed' | 'readiness-failed' | 'enable-failed' | 'supervision-lost' | 'close-unconfirmed';
/** Fixed code and (for setup) which step; never a request, reply, credential or exception message. */
export class ControllerError extends Error {
  readonly code: ControllerErrorCode;
  readonly step: string | undefined;
  constructor(code: ControllerErrorCode, step?: string) { super(step ? `${code}:${step}` : code); this.name = 'ControllerError'; this.code = code; this.step = step; }
}

export type RunLinks = { issuer: RoleLink; origin: RoleLink; clients: Record<ClientId, RoleLink> };
export type RunDeps = { links: RunLinks; redis: RedisPort; reset: ResetPort; gatewayLauncher?: GatewayLauncher; harness?: HarnessPort; faults?: FaultPort; vault?: Vault; retention?: RetentionPort;
  /** Settled origin counters collected by the reset barrier, used only when supervision closed the run before the scenario could read them itself. */
  finalOriginCounts?: () => Delta | null };
export type RunConfig = {
  /** Vouchers (and thus tokens) per client. The issuer inventory is exactly clients x perClient. */
  perClient: number;
  gatewayProfile?: GatewayProfile;
  clientProfile?: ClientProfile;
  heartbeatMs?: number;
  /** A heartbeat acknowledgement later than this closes the run (must stay below the lease). */
  ackDeadlineMs?: number;
  controlTimeoutMs?: number;
  /** After a close request, how long to wait for an in-flight setup step to notice the latch before the barrier runs anyway. */
  setupDrainMs?: number;
  /** Extra plaintext vouchers kept in controller memory for the security harness (theft, old-run and fault fixtures). */
  harnessVouchers?: number;
};
export type RunInfo = { run_id: string; config_digest: string; manifest: Manifest; incarnations: Record<string, string> };
export type CloseResult = { reason: string; reset_confirmed: boolean; error: ControllerErrorCode | null };
type Phase = 'idle' | 'setting-up' | 'enabled' | 'closing' | 'closed';

type Delta = { protected_requests_received: number; generation_mismatches: number; resources_served: number };
type Evidence = { origin: Delta; workers: number[]; client: Record<string, number> };
type Rule = { needsGateway: boolean; needsWorkers?: boolean; holds: (e: Evidence) => boolean };
const none = (e: Evidence) => e.origin.protected_requests_received === 0;
const one = (e: Evidence) => e.origin.protected_requests_received === 1 && e.origin.resources_served === 1 && e.origin.generation_mismatches === 0;
/** What the ORIGIN (and, where relevant, the gateway workers) must have seen, independent of anything a client claims. */
const ORIGIN_RULES: Record<string, Rule> = {
  'voucher-policy': { needsGateway: false, holds: none },
  'network-boundaries': { needsGateway: false, holds: none },
  'healthy-flow': { needsGateway: true, holds: one },
  'malformed-token': { needsGateway: true, holds: none },
  'signature-and-key': { needsGateway: true, holds: none },
  'wrong-context': { needsGateway: true, holds: none },
  'sequential-replay': { needsGateway: true, holds: one },
  // Exactly one arrival per winning trial, and verification attempts on EVERY configured worker (no worker-selection hook exists).
  'concurrent-replay': { needsGateway: true, needsWorkers: true, holds: (e) => {
    const wins = e.client['claims_successful'] ?? 0;
    return wins >= 1 && e.origin.protected_requests_received === wins && e.origin.resources_served === wins && e.origin.generation_mismatches === 0
      && e.workers.length > 0 && e.workers.every((attempts) => attempts > 0);
  } },
  // Five clients x two tokens: ten distinct first spends reached the origin, and nothing else did.
  'stolen-unused-token': { needsGateway: true, holds: one },
  // The new run: old credentials add nothing; the one fresh credential is the only arrival.
  'restart-and-reset': { needsGateway: true, holds: one },
  'redis-failure': { needsGateway: true, holds: none },
  'retention-audit': { needsGateway: false, holds: none },
  'clock-rollback': { needsGateway: true, holds: none },
  // The stalled origin may process the buffered request late (one arrival at most); a retry or refund would make it two.
  'upstream-failure': { needsGateway: true, holds: (e) => e.origin.protected_requests_received <= 1 && e.origin.generation_mismatches === 0 },
  'shared-egress': { needsGateway: true, holds: (e) => e.origin.protected_requests_received === 10 && e.origin.resources_served === 10 && e.origin.generation_mismatches === 0 },
};

const SECRETS = { issuer_cert: '/run/secrets/tls.crt', issuer_key: '/run/secrets/tls.key', ca: '/run/secrets/ca.crt' } as const;

export class LabRun {
  readonly #d: RunDeps;
  readonly #cfg: Required<RunConfig>;
  #phase: Phase = 'idle';
  #targets = new Map<string, Target>();
  #heartbeats: { stop: () => void }[] = [];
  #closing: Promise<CloseResult> | null = null;
  #info: RunInfo | null = null;
  readonly #closedWaiters: ((r: CloseResult) => void)[] = [];
  readonly #transitions: { state: string; reason: string }[] = [];
  readonly #scenarios: ScenarioRecord[] = [];
  #gateway: RoleLink | null = null;
  #manifest: Manifest | null = null;
  #harnessVouchers: string[] = [];
  #retention: RetentionCheck[] = [];
  #closeReason: string | null = null;
  /** Fixed check names that failed in the most recent scenario (operator output only). */
  lastFailed: string[] = [];
  #setupRun: Promise<unknown> | null = null;

  constructor(deps: RunDeps, config: RunConfig) {
    this.#d = deps;
    this.#cfg = {
      gatewayProfile: 'B1', clientProfile: 'demo', heartbeatMs: PROTOCOL.gateway_common.controller_heartbeat_ms, ackDeadlineMs: 1500,
      controlTimeoutMs: 10_000, setupDrainMs: 5_000, harnessVouchers: 0, ...config,
    };
    if (this.#cfg.ackDeadlineMs >= PROTOCOL.gateway_common.controller_lease_ms) throw new Error('ack deadline must be below the lease');
  }
  get phase(): Phase { return this.#phase; }
  get info(): RunInfo | null { return this.#info; }
  /** Incarnations discovered so far (available even if setup failed part-way, for the reset barrier). */
  get discovered(): Record<string, string> { return Object.fromEntries([...this.#targets].map(([n, t]) => [n, t.incarnation])); }
  /** The accepted manifest as soon as it exists (before setup finishes), for building the full reset snapshot. */
  get manifestSoFar(): Manifest | null { return this.#manifest; }
  /** Manifest facts the barrier needs, once they exist. */
  get runId(): string | null { return this.#info?.run_id ?? this.#targets.get('issuer')?.runId ?? null; }
  get configDigest(): string | null { return this.#info?.config_digest ?? this.#targets.get('issuer')?.digest ?? null; }
  /** Resolves once the run has closed (for any reason). */
  closed(): Promise<CloseResult> {
    return this.#phase === 'closed' && this.#closing ? this.#closing : new Promise((resolve) => this.#closedWaiters.push(resolve));
  }

  #links(): { name: string; link: RoleLink }[] {
    const l = this.#d.links;
    return [{ name: 'issuer', link: l.issuer }, { name: 'origin', link: l.origin },
      ...CLIENT_IDS.map((id) => ({ name: `client-${id}`, link: l.clients[id] })), ...(this.#gateway ? [{ name: 'gateway', link: this.#gateway }] : [])];
  }
  /**
   * Terminal cancellation latch. close() publishes its promise synchronously before any hook runs, so every await in
   * setup re-checks it: a delayed callback from an old setup step can never cause a later mutation or an ENABLE.
   */
  #guard(): void { if (this.#closing !== null) throw new ControllerError('setup-failed', 'cancelled'); }
  async #call(link: RoleLink, req: Json, step: string, expect: string, code: ControllerErrorCode = 'setup-failed'): Promise<Json> {
    this.#guard(); // before the request leaves: nothing is sent to a role once closing has begun
    let reply: Json;
    try { reply = await link.send(req, this.#cfg.controlTimeoutMs); } catch { this.#guard(); throw new ControllerError(code, step); }
    this.#guard();
    if (reply['ok'] !== true || reply['result'] !== expect) throw new ControllerError(code, step);
    return reply;
  }
  #at(name: string): Target { return this.#targets.get(name)!; }

  /** Builds and enables one run. On any failure the run is closed through the barrier before the error propagates. */
  async start(): Promise<RunInfo> {
    if (this.#phase !== 'idle') throw new ControllerError('setup-failed', 'already-started');
    this.#phase = 'setting-up';
    this.#transitions.push({ state: 'FENCED', reason: 'startup' });
    try {
      this.#setupRun = this.#setup();
      return await (this.#setupRun as Promise<RunInfo>);
    } catch (e) {
      const err = e instanceof ControllerError ? e : new ControllerError('setup-failed', 'unexpected');
      await this.close(err.code === 'role-not-fresh' || err.code === 'discovery-failed' ? 'configuration-mismatch' : 'unsafe-state');
      throw err;
    }
  }

  async #setup(): Promise<RunInfo> {
    const cfg = this.#cfg, d = this.#d;
    const clientProfile = cfg.clientProfile;
    // 1. Discover fresh incarnations; every role must be FENCED and must never have carried a run.
    for (const { name, link } of this.#links()) {
      let r: Json;
      this.#guard();
      try { r = await link.send(discovery(), cfg.controlTimeoutMs); } catch { this.#guard(); throw new ControllerError('discovery-failed', name); }
      this.#guard();
      if (r['ok'] !== true || r['result'] !== 'STATUS') throw new ControllerError('discovery-failed', name);
      if (r['state'] !== 'FENCED' || r['data']?.run_closed !== false || r['run_id'] !== null) throw new ControllerError('role-not-fresh', name);
      this.#targets.set(name, { incarnation: r['incarnation'], runId: null, digest: null });
    }
    if (new Set([...this.#targets.values()].map((t) => t.incarnation)).size !== this.#targets.size) throw new ControllerError('discovery-failed', 'duplicate-incarnation');

    // 2. Fresh run ID; the issuer generates its own key and returns public material only.
    const runId = newId();
    for (const t of this.#targets.values()) t.runId = runId;
    const issuerTarget = this.#at('issuer');
    const key = await this.#call(d.links.issuer, request('CREATE_ISSUER_KEY', { ...issuerTarget, digest: null }), 'create-issuer-key', 'KEY_CREATED');

    // 3. Replay store: exact scripts loaded and clock read while everything is fenced.
    let store: Awaited<ReturnType<RedisPort['prepare']>>;
    this.#guard();
    try { store = await d.redis.prepare(runId); } catch { this.#guard(); throw new ControllerError('setup-failed', 'redis-prepare'); }
    this.#guard();

    // 4. Public manifest and its digest, from the real key, scripts and clock.
    const total = cfg.perClient * CLIENT_IDS.length + cfg.harnessVouchers;
    let manifest: Manifest;
    try {
      manifest = makeManifest({ run_id: runId, run_start_ms: store.run_start_ms, token_key_spki_b64url: key['data'].token_key_spki_b64url,
        snapshot_script_sha1: store.snapshot_script_sha1, claim_script_sha1: store.claim_script_sha1,
        gateway_profile: cfg.gatewayProfile, client_profile: clientProfile, inventory_total: total });
    } catch { throw new ControllerError('setup-failed', 'manifest'); }
    // The issuer's own view of its key must be the one the manifest carries.
    if (manifest.token_key_id !== key['data'].token_key_id || encodeBase64Url(decodeBase64Url(manifest.token_key_spki_b64url), true) !== manifest.token_key_spki_b64url) {
      throw new ControllerError('setup-failed', 'key-mismatch');
    }
    const digest = configurationDigest(manifest);
    this.#manifest = manifest;

    // 5. Policy, clock and minimal ACLs for the accepted manifest; then the gateway's private startup input.
    let credentials: Awaited<ReturnType<RedisPort['install']>>;
    this.#guard(); // never install policy into a store once a reset may already be under way
    try { credentials = await d.redis.install(manifest, digest); } catch { this.#guard(); throw new ControllerError('setup-failed', 'redis-install'); }
    this.#guard();
    if (d.gatewayLauncher) {
      // The gateway creates its control socket only after it has received and validated its private startup input, so it
      // is launched first and discovered second. A launch that completes after close() is discarded, never adopted.
      let link: RoleLink;
      try { link = await d.gatewayLauncher.launch({ redis: credentials }); } catch { this.#guard(); throw new ControllerError('setup-failed', 'gateway-launch'); }
      if (this.#closing !== null) { try { link.close(); } catch { /* best effort */ } throw new ControllerError('setup-failed', 'cancelled'); }
      this.#gateway = link;
      let g: Json;
      try { g = await link.send(discovery(), cfg.controlTimeoutMs); } catch { this.#guard(); throw new ControllerError('discovery-failed', 'gateway'); }
      this.#guard();
      if (g['ok'] !== true || g['result'] !== 'STATUS') throw new ControllerError('discovery-failed', 'gateway');
      if (g['state'] !== 'FENCED' || g['data']?.run_closed !== false || g['run_id'] !== null) throw new ControllerError('role-not-fresh', 'gateway');
      this.#targets.set('gateway', { incarnation: g['incarnation'], runId, digest: null });
      if (new Set([...this.#targets.values()].map((t) => t.incarnation)).size !== this.#targets.size) throw new ControllerError('discovery-failed', 'duplicate-incarnation');
    }

    // 6. PREPARE every role. The initial PREPARE carries a null envelope digest and the proposed one in the payload.
    const prep = (role: string, roleConfig: Json) => request('PREPARE_RUN', { ...this.#at(role), digest: null }, { manifest, proposed_config_digest: digest, role, role_config: roleConfig });
    await this.#call(d.links.issuer, prep('issuer', { tls_cert_path: SECRETS.issuer_cert, tls_key_path: SECRETS.issuer_key }), 'prepare-issuer', 'PREPARED');
    await this.#call(d.links.origin, prep('origin', {}), 'prepare-origin', 'PREPARED');
    for (const id of CLIENT_IDS) {
      await this.#call(d.links.clients[id], request('PREPARE_RUN', { ...this.#at(`client-${id}`), digest: null }, { manifest, proposed_config_digest: digest, role: 'client',
        role_config: { client_id: id, ca_cert_path: SECRETS.ca } }), `prepare-client-${id}`, 'PREPARED');
    }
    if (this.#gateway) await this.#call(this.#gateway, prep('gateway', {}), 'prepare-gateway', 'PREPARED');
    for (const t of this.#targets.values()) t.digest = digest;
    this.#transitions.push({ state: 'PREPARED', reason: 'startup' });

    // 7. Provision the whole cohort now: bounded frames, explicit final seal, never again after ENABLE.
    const cohort = generateCohort(cfg.perClient, CLIENT_IDS, cfg.harnessVouchers);
    this.#harnessVouchers = [...cohort.harness];
    await this.#provision(d.links.issuer, 'issuer', 'PROVISION_VOUCHERS', cohort.issuerDigests, total);
    for (const id of CLIENT_IDS) await this.#provision(d.links.clients[id], `client-${id}`, 'PROVISION_CLIENT', cohort.clientItems[id], cfg.perClient);
    for (const id of CLIENT_IDS) cohort.clientItems[id].length = 0; // drop plaintext references; JS gives no stronger erasure guarantee
    cohort.issuerDigests.length = 0; cohort.harness.length = 0;

    // 8. READY everywhere. The gateway must report exactly the profile's worker count.
    const ready = async (name: string, link: RoleLink, workers: number) => {
      const r = await this.#call(link, request('CHECK_READY', this.#at(name)), `ready-${name}`, 'READY', 'readiness-failed');
      if (r['data'].workers_ready !== workers) throw new ControllerError('readiness-failed', name);
    };
    await ready('issuer', d.links.issuer, 1); await ready('origin', d.links.origin, 1);
    for (const id of CLIENT_IDS) await ready(`client-${id}`, d.links.clients[id], 1);
    if (this.#gateway) await ready('gateway', this.#gateway, manifest.limits.gateway.workers);
    this.#transitions.push({ state: 'READY', reason: 'ready' });

    // 9. Enable: origin and clients, then the issuer (its lease starts now, so supervision starts at once), then the gateway LAST.
    const enable = async (name: string, link: RoleLink, workers: number) => {
      const r = await this.#call(link, request('ENABLE', this.#at(name)), `enable-${name}`, 'ENABLED', 'enable-failed');
      if (r['data'].workers_enabled !== workers) throw new ControllerError('enable-failed', name);
    };
    await enable('origin', d.links.origin, 1);
    await Promise.all(CLIENT_IDS.map((id) => enable(`client-${id}`, d.links.clients[id], 1)));
    await enable('issuer', d.links.issuer, 1);
    this.#guard();
    this.#phase = 'enabled';
    this.#transitions.push({ state: 'ENABLED', reason: 'enabled' });
    this.#supervise('issuer', d.links.issuer);
    if (this.#gateway) {
      await enable('gateway', this.#gateway, manifest.limits.gateway.workers);
      this.#supervise('gateway', this.#gateway);
    }
    const incarnations = Object.fromEntries([...this.#targets].map(([n, t]) => [n, t.incarnation]));
    this.#info = { run_id: runId, config_digest: digest, manifest, incarnations };
    return this.#info;
  }

  async #provision(link: RoleLink, name: string, command: 'PROVISION_VOUCHERS' | 'PROVISION_CLIENT', items: readonly string[], total: number): Promise<void> {
    const batchId = newId();
    const frames = [...batches(items)];
    for (let i = 0; i < frames.length; i++) {
      const last = i === frames.length - 1;
      const r = await this.#call(link, request(command, this.#at(name), { batch_id: batchId, batch_index: i, expected_total: total, final_batch: last, items: frames[i] }),
        `provision-${name}`, 'PROVISIONED');
      if (last && (r['data'].sealed !== true || r['data'].received_total !== total)) throw new ControllerError('setup-failed', `seal-${name}`);
    }
  }

  /** Sequenced heartbeats, one outstanding per link. Any late, missing, erroring or misnumbered acknowledgement closes the run. */
  #supervise(name: string, link: RoleLink): void {
    let stopped = false, seq = 0, timer: NodeJS.Timeout | null = null;
    const loop = async () => {
      if (stopped) return;
      const started = performance.now();
      seq += 1;
      try {
        const reply = await link.send(request('HEARTBEAT', this.#at(name), { seq }), this.#cfg.ackDeadlineMs);
        if (stopped) return;
        if (reply['ok'] !== true || reply['result'] !== 'HEARTBEAT_ACK' || reply['data'].seq !== seq) throw new Error('bad-ack');
      } catch {
        if (!stopped) void this.close('control-lost');
        return;
      }
      if (stopped) return;
      timer = setTimeout(() => void loop(), Math.max(0, this.#cfg.heartbeatMs - (performance.now() - started)));
    };
    void loop();
    this.#heartbeats.push({ stop: () => { stopped = true; if (timer) clearTimeout(timer); } });
  }


  /** Origin's settled aggregate counters right now, or null when it cannot be read or is mid-request (never a guess). */
  async #originCounts(): Promise<Delta | null> {
    try {
      const r = await this.#d.links.origin.send(request('REPORT', this.#at('origin')), this.#cfg.controlTimeoutMs);
      if (r['ok'] !== true || r['data'].origin_counts_available !== true) return null;
      const c = r['data'].counters;
      return { protected_requests_received: c.protected_requests_received, generation_mismatches: c.generation_mismatches, resources_served: c.resources_served };
    } catch { return null; }
  }
  async #workerAttempts(): Promise<Map<number, number> | null> {
    const g = this.#gateway;
    if (!g) return null;
    try {
      const r = await g.send(request('REPORT', this.#at('gateway')), this.#cfg.controlTimeoutMs);
      if (r['ok'] !== true) return null;
      return new Map((r['data'].worker_verification_attempts as { worker_index: number; attempts: number }[]).map((w) => [w.worker_index, w.attempts]));
    } catch { return null; }
  }

  /**
   * Runs one named scenario on one client and merges the client's own result with INDEPENDENT evidence read from the
   * origin (and gateway workers) before and after. A client PASS alone is never enough: without origin evidence, or if
   * the origin saw what the scenario says it must not, the record is INCONCLUSIVE or FAIL. A scenario that needs the
   * gateway cannot PASS in a gatewayless run.
   */
  async runScenario(clients: ClientId | readonly ClientId[], scenarioId: string, seed = 1): Promise<ScenarioRecord> {
    const ids = typeof clients === 'string' ? [clients] : [...clients];
    return this.#measure(scenarioId, async () => {
      const replies = await Promise.all(ids.map(async (id): Promise<Json | null> => {
        try { return await this.#d.links.clients[id].send(request('RUN_SCENARIO', this.#at(`client-${id}`), { scenario_id: scenarioId, schedule_seed: seed }), 180_000); }
        catch { return null; }
      }));
      if (replies.some((r) => r === null)) return 'control-lost';
      if (replies.some((r) => r!['ok'] !== true || r!['result'] !== 'SCENARIO_COMPLETE')) return 'missing-evidence';
      return replies.map((r) => r!['data'] as ScenarioData);
    });
  }

  /** Vouchers for the security harness, removed from controller memory as they are handed out. */
  #takeHarnessVouchers(n: number): string[] | null {
    if (this.#harnessVouchers.length < n) return null;
    return this.#harnessVouchers.splice(0, n);
  }

  /**
   * Controller-orchestrated scenarios (real faults, credentials crossing processes). `key` is a scenario id, or
   * `id:variant` for fault families. The report row carries the scenario id; the same independent origin evidence applies.
   */
  async runOrchestrated(key: string): Promise<ScenarioRecord> {
    const handler = ORCHESTRATED[key];
    const id = REDIS_FAULT_SCENARIOS[key]?.id ?? key;
    const ctx: OrchestrationContext = {
      manifest: this.#manifest!, harness: this.#d.harness, faults: this.#d.faults, vault: this.#d.vault ?? (this.#d.vault = new Vault()),
      takeVouchers: (n) => this.#takeHarnessVouchers(n),
      closing: () => ({ closing: this.#closing !== null, reason: this.#closeReason }),
      gatewayStatus: async () => { if (!this.#gateway) return null; try { return await this.#gateway.send(request('STATUS', this.#at('gateway')), this.#cfg.controlTimeoutMs); } catch { return null; } },
      sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    };
    if (key === 'retention-audit') {
      return this.#measure(id, async () => {
        if (!this.#d.retention) return 'missing-evidence';
        let checks: RetentionCheck[];
        try { checks = await this.#d.retention.audit(); } catch { return 'control-lost'; }
        this.#retention = checks;
        const bad = checks.filter((c) => c.status !== 'PASS');
        return [{ status: checks.some((c) => c.status === 'FAIL') ? 'FAIL' : bad.length > 0 ? 'INCONCLUSIVE' : 'PASS', expected: 'retention',
          counters: { observations: checks.length }, failure_labels: bad.length > 0 ? ['assertion-failed'] : [], failed: bad.map((c) => `${c.check_id}:${c.status}`) }];
      });
    }
    return this.#measure(id, async () => {
      if (!handler) return 'missing-evidence';
      try { return [await handler(ctx)]; } catch { return 'control-lost'; }
    });
  }

  /** Hidden S13 part 1: quarantine one spent and one unused credential across the coming reset. Produces no report row. */
  async captureForReset(): Promise<boolean> {
    if (this.#phase !== 'enabled') throw new ControllerError('setup-failed', 'not-enabled');
    const ctx: OrchestrationContext = {
      manifest: this.#manifest!, harness: this.#d.harness, faults: this.#d.faults, vault: this.#d.vault ?? (this.#d.vault = new Vault()),
      takeVouchers: (n) => this.#takeHarnessVouchers(n), gatewayStatus: async () => null, closing: () => ({ closing: this.#closing !== null, reason: this.#closeReason }), sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    };
    try { return await captureOldCredentials(ctx); } catch { return false; }
  }

  async #measure(scenarioId: string, exec: () => Promise<ScenarioData[] | 'control-lost' | 'missing-evidence'>): Promise<ScenarioRecord> {
    if (this.#phase !== 'enabled') throw new ControllerError('setup-failed', 'not-enabled');
    const before = await this.#originCounts(), workersBefore = await this.#workerAttempts();
    const outcome = await exec();
    let after = await this.#originCounts();
    const workersAfter = await this.#workerAttempts();
    // A fault scenario can end with supervision closing the run before the live read; the barrier's settled REPORT is then the evidence.
    if (!after && this.#closing) { await this.#closing; after = this.#d.finalOriginCounts?.() ?? null; }

    const record: ScenarioRecord = { scenario_id: scenarioId, status: 'INCONCLUSIVE', expected: 'accepted', counters: {}, origin_counts_available: false, worker_verification_attempts: [], failure_labels: [] };
    if (typeof outcome === 'string') {
      // A scenario that is not implemented or could not be reached is NOT TESTED, never a failure or a pass.
      record.failure_labels = [outcome];
      this.#scenarios.push(record);
      return record;
    }
    const datas = outcome;
    this.lastFailed = datas.flatMap((d) => d.failed ?? []);
    record.expected = datas[0]!.expected;
    const summed: Record<string, number> = {};
    for (const d of datas) for (const [k, v] of Object.entries(d.counters)) summed[k] = (summed[k] ?? 0) + v;
    const labels = new Set<string>(datas.flatMap((d) => d.failure_labels));
    const delta: Delta | null = before && after ? {
      protected_requests_received: after.protected_requests_received - before.protected_requests_received,
      generation_mismatches: after.generation_mismatches - before.generation_mismatches,
      resources_served: after.resources_served - before.resources_served,
    } : null;
    const clientCounters = { ...summed };
    record.counters = { ...summed };
    if (delta) { record.origin_counts_available = true; Object.assign(record.counters, delta); }
    if (workersBefore && workersAfter) {
      record.worker_verification_attempts = [...workersAfter].map(([worker_index, attempts]) => ({ worker_index, attempts: attempts - (workersBefore.get(worker_index) ?? 0) }))
        .sort((a, b) => a.worker_index - b.worker_index);
    }
    const rule = ORIGIN_RULES[scenarioId];
    const statuses = datas.map((d) => d.status as string);
    if (statuses.includes('FAIL')) record.status = 'FAIL';
    else if (statuses.some((st) => st !== 'PASS')) record.status = 'INCONCLUSIVE';
    else if (!rule || (rule.needsGateway && !this.#gateway) || !delta || (rule.needsWorkers && (!workersAfter || record.worker_verification_attempts.length === 0))) { record.status = 'INCONCLUSIVE'; labels.add('missing-evidence'); }
    else if (!rule.holds({ origin: delta, workers: record.worker_verification_attempts.map((w) => w.attempts), client: clientCounters })) { record.status = 'FAIL'; labels.add('assertion-failed'); }
    else record.status = 'PASS';
    record.failure_labels = [...labels];
    this.#scenarios.push(record);
    return record;
  }

  /** The evidence gathered so far, in the report's run shape. Safe at any phase; an unfinished run is visibly so. */
  runRecord(retention: RunRecord['retention_checks'] = this.#retention): RunRecord | null {
    if (!this.#info) return null;
    const m = this.#info.manifest;
    return {
      run_id: this.#info.run_id, config_digest: this.#info.config_digest, token_key_id: m.token_key_id, gateway_profile: m.gateway_profile,
      client_profile: m.client_profile, origin_incarnation: this.#targets.get('origin')?.incarnation ?? null, scenario_results: [...this.#scenarios],
      measurements: [], state_transitions: [...this.#transitions], retention_checks: retention,
    };
  }

  /** A watched container/process exited or changed incarnation (from the Docker event monitor). */
  roleLost(_name: string): void { void this.close('process-exited'); }

  /** Operator stop. Same path as a fault: barrier first, then Redis discard. Idempotent. */
  stop(reason: string = 'operator-stop'): Promise<CloseResult> { return this.close(reason); }

  close(reason: string): Promise<CloseResult> {
    if (this.#closing) return this.#closing;
    // Publish the one cached promise FIRST, synchronously, before any reentrant hook or await can observe `null`.
    let finish!: (r: CloseResult) => void;
    this.#closing = new Promise<CloseResult>((resolve) => { finish = resolve; });
    this.#phase = 'closing';
    this.#closeReason = reason;
    const why = (PROTOCOL.faults as readonly string[]).includes(reason) ? reason : 'completed';
    this.#transitions.push({ state: 'CLOSING', reason: why });
    for (const h of this.#heartbeats) h.stop();
    void (async () => {
      // Give an in-flight setup step a bounded moment to reach its next guard and unwind; a step that never returns does not
      // block the barrier, which acts on container identities and so covers whatever that step created.
      if (this.#setupRun) {
        let timer: NodeJS.Timeout | undefined;
        await Promise.race([this.#setupRun.then(() => undefined, () => undefined), new Promise<void>((r) => { timer = setTimeout(r, this.#cfg.setupDrainMs); timer.unref(); })]);
        clearTimeout(timer);
      }
      let result: CloseResult;
      try {
        const receipt = await this.#d.reset.fenceAll();
        await this.#d.reset.discardOldRedis(receipt);
        result = { reason, reset_confirmed: true, error: null };
      } catch {
        // Could not prove the old generation is gone: stay closed. No retry, no fresh setup permission.
        result = { reason, reset_confirmed: false, error: 'close-unconfirmed' };
      }
      for (const { link } of this.#links()) { try { link.close(); } catch { /* every link is closed even if one throws */ } }
      this.#phase = 'closed';
      this.#transitions.push({ state: 'FENCED', reason: why });
      finish(result);
      for (const w of this.#closedWaiters.splice(0)) w(result);
    })();
    return this.#closing;
  }
}
