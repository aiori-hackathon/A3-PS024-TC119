// The foreground run controller (plan sections 5.2 to 5.5, 9.1). It holds no state that survives the process: it
// discovers fresh role incarnations, builds one run in the exact startup order, supervises it with sequenced heartbeats
// (one outstanding per link), and on ANY unsafe event closes through the strong reset barrier. It never retries a
// mutation, never replenishes vouchers, and never reopens a closed run. Failure to confirm shutdown leaves it closed.
import {
  PROTOCOL, makeManifest, configurationDigest, encodeBase64Url, decodeBase64Url, type Manifest, type ClientProfile, type GatewayProfile,
} from '../../../../contracts/lib/index.ts';
import { CLIENT_IDS, type ClientId, type GatewayLauncher, type Json, type RedisPort, type ResetPort, type RoleLink } from './ports.ts';
import { discovery, newId, request, type Target } from './envelope.ts';
import { batches, generateCohort } from './cohort.ts';

export type ControllerErrorCode =
  | 'discovery-failed' | 'role-not-fresh' | 'setup-failed' | 'readiness-failed' | 'enable-failed' | 'supervision-lost' | 'close-unconfirmed';
/** Fixed code and (for setup) which step; never a request, reply, credential or exception message. */
export class ControllerError extends Error {
  readonly code: ControllerErrorCode;
  readonly step: string | undefined;
  constructor(code: ControllerErrorCode, step?: string) { super(step ? `${code}:${step}` : code); this.name = 'ControllerError'; this.code = code; this.step = step; }
}

export type RunLinks = { issuer: RoleLink; origin: RoleLink; clients: Record<ClientId, RoleLink>; gateway?: RoleLink };
export type RunDeps = { links: RunLinks; redis: RedisPort; reset: ResetPort; gatewayLauncher?: GatewayLauncher };
export type RunConfig = {
  /** Vouchers (and thus tokens) per client. The issuer inventory is exactly clients x perClient. */
  perClient: number;
  gatewayProfile?: GatewayProfile;
  clientProfile?: ClientProfile;
  heartbeatMs?: number;
  /** A heartbeat acknowledgement later than this closes the run (must stay below the lease). */
  ackDeadlineMs?: number;
  controlTimeoutMs?: number;
};
export type RunInfo = { run_id: string; config_digest: string; manifest: Manifest; incarnations: Record<string, string> };
export type CloseResult = { reason: string; reset_confirmed: boolean; error: ControllerErrorCode | null };
type Phase = 'idle' | 'setting-up' | 'enabled' | 'closing' | 'closed';

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

  constructor(deps: RunDeps, config: RunConfig) {
    this.#d = deps;
    this.#cfg = {
      gatewayProfile: 'B1', clientProfile: 'demo', heartbeatMs: PROTOCOL.gateway_common.controller_heartbeat_ms, ackDeadlineMs: 1500,
      controlTimeoutMs: 10_000, ...config,
    };
    if (this.#cfg.ackDeadlineMs >= PROTOCOL.gateway_common.controller_lease_ms) throw new Error('ack deadline must be below the lease');
  }
  get phase(): Phase { return this.#phase; }
  get info(): RunInfo | null { return this.#info; }
  /** Incarnations discovered so far (available even if setup failed part-way, for the reset barrier). */
  get discovered(): Record<string, string> { return Object.fromEntries([...this.#targets].map(([n, t]) => [n, t.incarnation])); }
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
      ...CLIENT_IDS.map((id) => ({ name: `client-${id}`, link: l.clients[id] })), ...(l.gateway ? [{ name: 'gateway', link: l.gateway }] : [])];
  }
  async #call(link: RoleLink, req: Json, step: string, expect: string, code: ControllerErrorCode = 'setup-failed'): Promise<Json> {
    let reply: Json;
    try { reply = await link.send(req, this.#cfg.controlTimeoutMs); } catch { throw new ControllerError(code, step); }
    if (reply['ok'] !== true || reply['result'] !== expect) throw new ControllerError(code, step);
    return reply;
  }
  #at(name: string): Target { return this.#targets.get(name)!; }

  /** Builds and enables one run. On any failure the run is closed through the barrier before the error propagates. */
  async start(): Promise<RunInfo> {
    if (this.#phase !== 'idle') throw new ControllerError('setup-failed', 'already-started');
    this.#phase = 'setting-up';
    try {
      return await this.#setup();
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
      try { r = await link.send(discovery(), cfg.controlTimeoutMs); } catch { throw new ControllerError('discovery-failed', name); }
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
    try { store = await d.redis.prepare(runId); } catch { throw new ControllerError('setup-failed', 'redis-prepare'); }

    // 4. Public manifest and its digest, from the real key, scripts and clock.
    const total = cfg.perClient * CLIENT_IDS.length;
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

    // 5. Policy, clock and minimal ACLs for the accepted manifest; then the gateway's private startup input.
    let credentials: Awaited<ReturnType<RedisPort['install']>>;
    try { credentials = await d.redis.install(manifest, digest); } catch { throw new ControllerError('setup-failed', 'redis-install'); }
    if (d.links.gateway) {
      if (!d.gatewayLauncher) throw new ControllerError('setup-failed', 'gateway-launcher');
      try { await d.gatewayLauncher.launch({ redis: credentials }); } catch { throw new ControllerError('setup-failed', 'gateway-launch'); }
    }

    // 6. PREPARE every role. The initial PREPARE carries a null envelope digest and the proposed one in the payload.
    const prep = (role: string, roleConfig: Json) => request('PREPARE_RUN', { ...this.#at(role), digest: null }, { manifest, proposed_config_digest: digest, role, role_config: roleConfig });
    await this.#call(d.links.issuer, prep('issuer', { tls_cert_path: SECRETS.issuer_cert, tls_key_path: SECRETS.issuer_key }), 'prepare-issuer', 'PREPARED');
    await this.#call(d.links.origin, prep('origin', {}), 'prepare-origin', 'PREPARED');
    for (const id of CLIENT_IDS) {
      await this.#call(d.links.clients[id], request('PREPARE_RUN', { ...this.#at(`client-${id}`), digest: null }, { manifest, proposed_config_digest: digest, role: 'client',
        role_config: { client_id: id, ca_cert_path: SECRETS.ca } }), `prepare-client-${id}`, 'PREPARED');
    }
    if (d.links.gateway) await this.#call(d.links.gateway, prep('gateway', {}), 'prepare-gateway', 'PREPARED');
    for (const t of this.#targets.values()) t.digest = digest;

    // 7. Provision the whole cohort now: bounded frames, explicit final seal, never again after ENABLE.
    const cohort = generateCohort(cfg.perClient);
    await this.#provision(d.links.issuer, 'issuer', 'PROVISION_VOUCHERS', cohort.issuerDigests, total);
    for (const id of CLIENT_IDS) await this.#provision(d.links.clients[id], `client-${id}`, 'PROVISION_CLIENT', cohort.clientItems[id], cfg.perClient);
    for (const id of CLIENT_IDS) cohort.clientItems[id].length = 0; // drop plaintext references; JS gives no stronger erasure guarantee
    cohort.issuerDigests.length = 0;

    // 8. READY everywhere. The gateway must report exactly the profile's worker count.
    const ready = async (name: string, link: RoleLink, workers: number) => {
      const r = await this.#call(link, request('CHECK_READY', this.#at(name)), `ready-${name}`, 'READY', 'readiness-failed');
      if (r['data'].workers_ready !== workers) throw new ControllerError('readiness-failed', name);
    };
    await ready('issuer', d.links.issuer, 1); await ready('origin', d.links.origin, 1);
    for (const id of CLIENT_IDS) await ready(`client-${id}`, d.links.clients[id], 1);
    if (d.links.gateway) await ready('gateway', d.links.gateway, manifest.limits.gateway.workers);

    // 9. Enable: origin and clients, then the issuer (its lease starts now, so supervision starts at once), then the gateway LAST.
    const enable = async (name: string, link: RoleLink, workers: number) => {
      const r = await this.#call(link, request('ENABLE', this.#at(name)), `enable-${name}`, 'ENABLED', 'enable-failed');
      if (r['data'].workers_enabled !== workers) throw new ControllerError('enable-failed', name);
    };
    await enable('origin', d.links.origin, 1);
    await Promise.all(CLIENT_IDS.map((id) => enable(`client-${id}`, d.links.clients[id], 1)));
    await enable('issuer', d.links.issuer, 1);
    this.#phase = 'enabled';
    this.#supervise('issuer', d.links.issuer);
    if (d.links.gateway) {
      await enable('gateway', d.links.gateway, manifest.limits.gateway.workers);
      this.#supervise('gateway', d.links.gateway);
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

  /** A watched container/process exited or changed incarnation (from the Docker event monitor). */
  roleLost(_name: string): void { void this.close('process-exited'); }

  /** Operator stop. Same path as a fault: barrier first, then Redis discard. Idempotent. */
  stop(reason: string = 'operator-stop'): Promise<CloseResult> { return this.close(reason); }

  close(reason: string): Promise<CloseResult> {
    if (this.#closing) return this.#closing;
    this.#phase = 'closing';
    for (const h of this.#heartbeats) h.stop();
    this.#closing = (async (): Promise<CloseResult> => {
      let result: CloseResult;
      try {
        const receipt = await this.#d.reset.fenceAll();
        await this.#d.reset.discardOldRedis(receipt);
        result = { reason, reset_confirmed: true, error: null };
      } catch {
        // Could not prove the old generation is gone: stay closed. No retry, no fresh setup permission.
        result = { reason, reset_confirmed: false, error: 'close-unconfirmed' };
      }
      for (const { link } of this.#links()) link.close();
      this.#phase = 'closed';
      for (const w of this.#closedWaiters.splice(0)) w(result);
      return result;
    })();
    return this.#closing;
  }
}
