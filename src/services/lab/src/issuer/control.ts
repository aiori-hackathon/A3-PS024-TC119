// Issuer role lifecycle (plan section 5): FENCED -> PREPARED -> READY -> ENABLED -> CLOSING -> FENCED, any unsafe
// event -> FAULTED. Transport-agnostic: handle() takes one parsed control request and returns one reply.
// Nothing here exports the signing key, mints a second key, or accepts vouchers after enable.
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:https';
import {
  PROTOCOL, ContractError, encodeBase64Url, hex, sha256, validateControlRequest, validateControlResponse, type Manifest,
} from '../../../../contracts/lib/index.ts';
import { LabError, type ControlErrorResult } from '../errors.ts';
import { LabIssuer } from '../protocol.ts';
import { VoucherStore } from './vouchers.ts';
import { IssuanceService } from './issuance.ts';
import { createIssuerServer, type IssuerTls } from './server.ts';

type State = 'FENCED' | 'PREPARED' | 'READY' | 'ENABLED' | 'CLOSING' | 'FAULTED';
type Fault = (typeof PROTOCOL.faults)[number] | null;
type Json = Record<string, unknown>;

export type IssuerRoleOptions = {
  /** Reads a path under /run/secrets. Injected for tests. */
  readSecret?: (path: string) => Buffer;
  /** Monotonic milliseconds. Injected for tests. */
  clock?: () => number;
  listen?: { host: string; port: number };
  /** Bound on waiting for in-flight signings to settle during FENCE. */
  drainMs?: number;
};

export class IssuerRole {
  readonly incarnation = hex(randomBytes(16));
  readonly #readSecret: (path: string) => Buffer;
  readonly #now: () => number;
  readonly #listen: { host: string; port: number };
  readonly #drainMs: number;
  #state: State = 'FENCED';
  #fault: Fault = null;
  #runClosed = false;
  #runId: string | null = null;
  #digest: string | null = null;
  #manifest: Manifest | null = null;
  #issuer: LabIssuer | null = null;
  #keyReply: { request_id: string; data: Json } | null = null;
  #tls: IssuerTls | null = null;
  #vouchers: VoucherStore | null = null;
  #service: IssuanceService | null = null;
  #server: Server | null = null;
  #leaseExpiry = 0;
  #watchdog: NodeJS.Timeout | null = null;
  #lastSeq = 0;
  #chain: Promise<unknown> = Promise.resolve();

  constructor(options: IssuerRoleOptions = {}) {
    this.#readSecret = options.readSecret ?? ((p) => readFileSync(p));
    this.#now = options.clock ?? (() => performance.now());
    this.#listen = options.listen ?? { host: '0.0.0.0', port: 443 };
    this.#drainMs = options.drainMs ?? 8000;
  }

  get state(): State { return this.#state; }
  /** Bound issuance listener address once enabled (tests and health only). */
  get address(): AddressInfo | null { return (this.#server?.address() as AddressInfo | null) ?? null; }

  async handle(raw: unknown): Promise<Json> {
    const id = (raw as { request_id?: unknown } | null)?.request_id;
    const requestId = typeof id === 'string' && /^[0-9a-f]{32}$/.test(id) ? id : '0'.repeat(32);
    try {
      if ((raw as { version?: unknown } | null)?.version !== 1) throw new LabError('BAD_VERSION');
      let req: Json;
      try { req = validateControlRequest(raw); } catch (e) { if (e instanceof ContractError) throw new LabError('BAD_MESSAGE'); throw e; }
      const command = req['command'] as string;
      this.#checkEnvelope(req, command);
      // FENCE, STATUS and HEARTBEAT are never queued behind a mutation in progress.
      if (command === 'STATUS') return this.#ok(requestId, 'STATUS', { ready: this.#state === 'READY' || this.#state === 'ENABLED', run_closed: this.#runClosed, fault: this.#fault });
      if (command === 'REPORT') return this.report(requestId);
      if (command === 'FENCE') return await this.#fence(requestId, (req['payload'] as Json)['reason'] as Fault);
      if (command === 'HEARTBEAT') return this.#heartbeat(requestId, (req['payload'] as Json)['seq'] as number);
      const run = this.#chain.then(() => this.#mutate(requestId, command, req), () => this.#mutate(requestId, command, req));
      this.#chain = run.catch(() => undefined);
      return await run;
    } catch (e) {
      return this.#error(requestId, e instanceof LabError ? e.result : 'FAULTED');
    }
  }

  #checkEnvelope(req: Json, command: string): void {
    const discovery = command === 'STATUS' || command === 'FENCE';
    const target = req['target_incarnation'] as string | null;
    // Only discovery commands may omit the target; FENCE/STATUS may also carry a stale run and still act.
    if (target === null ? !discovery : target !== this.incarnation) throw new LabError('WRONG_INCARNATION');
    if (discovery || command === 'CREATE_ISSUER_KEY') return;
    if (req['run_id'] !== this.#runId) throw new LabError('WRONG_RUN');
    if (command !== 'PREPARE_RUN' && req['config_digest'] !== this.#digest) throw new LabError('WRONG_CONFIG');
  }

  async #mutate(requestId: string, command: string, req: Json): Promise<Json> {
    try {
      switch (command) {
        case 'CREATE_ISSUER_KEY': return await this.#createKey(requestId, req['run_id'] as string);
        case 'PREPARE_RUN': return this.#prepare(requestId, req['payload'] as Json);
        case 'PROVISION_VOUCHERS': return this.#provision(requestId, req['payload'] as never);
        case 'CHECK_READY': return this.#checkReady(requestId);
        case 'ENABLE': return await this.#enable(requestId);
        default: throw new LabError('ILLEGAL_STATE'); // client/scenario commands do not belong to the issuer
      }
    } catch (e) {
      if (e instanceof LabError) return this.#error(requestId, e.result);
      this.#faultNow('unsafe-state'); // unknown failure during a mutation: close rather than guess
      return this.#error(requestId, 'FAULTED');
    }
  }

  async #createKey(requestId: string, runId: string): Promise<Json> {
    if (this.#keyReply && this.#runId === runId && this.#keyReply.request_id === requestId) return this.#ok(requestId, 'KEY_CREATED', this.#keyReply.data);
    if (this.#state !== 'FENCED' || this.#runClosed || this.#issuer) throw new LabError('ILLEGAL_STATE');
    this.#issuer = await LabIssuer.generate(PROTOCOL.issuer_name);
    this.#runId = runId;
    const data = { token_key_spki_b64url: encodeBase64Url(this.#issuer.publicKeySpki, true), token_key_id: hex(sha256(this.#issuer.publicKeySpki)) };
    this.#keyReply = { request_id: requestId, data };
    return this.#ok(requestId, 'KEY_CREATED', data);
  }

  #prepare(requestId: string, payload: Json): Json {
    if (this.#state !== 'FENCED' || this.#runClosed || !this.#issuer || this.#digest !== null) throw new LabError('ILLEGAL_STATE');
    if (payload['role'] !== 'issuer') throw new LabError('BAD_MESSAGE');
    const manifest = payload['manifest'] as Manifest;
    // The manifest must describe the key this process generated, not merely a well-formed key.
    if (manifest.run_id !== this.#runId || manifest.token_key_id !== hex(sha256(this.#issuer.publicKeySpki))
      || manifest.token_key_spki_b64url !== encodeBase64Url(this.#issuer.publicKeySpki, true)) throw new LabError('WRONG_CONFIG');
    const cfg = payload['role_config'] as { tls_cert_path?: string; tls_key_path?: string };
    if (!cfg.tls_cert_path || !cfg.tls_key_path) throw new LabError('BAD_MESSAGE');
    try { this.#tls = { cert: this.#readSecret(cfg.tls_cert_path), key: this.#readSecret(cfg.tls_key_path) }; } catch { throw new LabError('DEPENDENCY_UNAVAILABLE'); }
    this.#manifest = manifest;
    this.#digest = payload['proposed_config_digest'] as string;
    this.#vouchers = new VoucherStore(manifest.inventory_total);
    this.#service = new IssuanceService(this.#issuer, this.#vouchers, manifest.limits.issuer);
    this.#state = 'PREPARED';
    return this.#ok(requestId, 'PREPARED', {});
  }

  #provision(requestId: string, payload: Parameters<VoucherStore['provision']>[0]): Json {
    if (this.#state !== 'PREPARED' || !this.#vouchers) throw new LabError('ILLEGAL_STATE');
    return this.#ok(requestId, 'PROVISIONED', this.#vouchers.provision(payload));
  }

  #checkReady(requestId: string): Json {
    if (this.#state === 'READY') return this.#ok(requestId, 'READY', { workers_ready: 1 });
    if (this.#state !== 'PREPARED' || !this.#vouchers?.sealed || !this.#tls) throw new LabError('ILLEGAL_STATE');
    this.#state = 'READY';
    return this.#ok(requestId, 'READY', { workers_ready: 1 });
  }

  async #enable(requestId: string): Promise<Json> {
    if (this.#state === 'ENABLED') { // repeat ENABLE acknowledges; it never renews or reopens
      this.#expireIfStale();
      if (this.#state === 'ENABLED') return this.#ok(requestId, 'ENABLED', { workers_enabled: 1 });
      throw new LabError('FAULTED');
    }
    if (this.#state !== 'READY' || !this.#manifest || !this.#vouchers || !this.#service || !this.#issuer || !this.#tls) throw new LabError('ILLEGAL_STATE');
    this.#vouchers.lock();
    this.#leaseExpiry = this.#now() + this.#manifest.limits.gateway.controller_lease_ms;
    this.#server = createIssuerServer(this.#service, this.#issuer.publicKeySpki, this.#tls);
    try {
      await new Promise<void>((resolve, reject) => { this.#server!.once('error', reject); this.#server!.listen(this.#listen.port, this.#listen.host, () => resolve()); });
    } catch { this.#faultNow('dependency-lost'); throw new LabError('FAULTED'); }
    if (this.#state !== 'READY') { this.#closeAdmission(); throw new LabError('FAULTED'); } // fenced while binding
    if (this.#now() >= this.#leaseExpiry) { this.#faultNow('lease-expired'); throw new LabError('FAULTED'); }
    this.#state = 'ENABLED';
    this.#service.setOpen(true);
    this.#armWatchdog();
    return this.#ok(requestId, 'ENABLED', { workers_enabled: 1 });
  }

  #heartbeat(requestId: string, seq: number): Json {
    if (this.#state !== 'ENABLED') throw new LabError(this.#state === 'FAULTED' ? 'FAULTED' : 'ILLEGAL_STATE');
    // Expiry is judged synchronously before any renewal, so a late heartbeat cannot revive an expired run.
    this.#expireIfStale();
    if (this.#state !== 'ENABLED') throw new LabError('FAULTED');
    if (seq <= this.#lastSeq) throw new LabError('BAD_MESSAGE');
    this.#lastSeq = seq;
    this.#leaseExpiry = this.#now() + this.#manifest!.limits.gateway.controller_lease_ms;
    this.#armWatchdog();
    return this.#ok(requestId, 'HEARTBEAT_ACK', { seq });
  }

  #expireIfStale(): void { if (this.#state === 'ENABLED' && this.#now() >= this.#leaseExpiry) this.#faultNow('lease-expired'); }

  #armWatchdog(): void {
    if (this.#watchdog) clearTimeout(this.#watchdog);
    const wait = Math.max(0, this.#leaseExpiry - this.#now());
    this.#watchdog = setTimeout(() => this.#expireIfStale(), wait + 1);
    this.#watchdog.unref();
  }

  /** Stop admitting and drop connections immediately; latches the run closed. Safe to call repeatedly. */
  #faultNow(reason: Fault): void {
    if (this.#state !== 'FAULTED') { this.#state = 'FAULTED'; this.#fault = reason; }
    this.#runClosed = true;
    this.#closeAdmission();
  }

  #closeAdmission(): void {
    if (this.#watchdog) { clearTimeout(this.#watchdog); this.#watchdog = null; }
    this.#service?.setOpen(false);
    this.#vouchers?.clear();
    const server = this.#server;
    if (server) { server.closeAllConnections(); server.close(); }
  }

  async #fence(requestId: string, reason: Fault): Promise<Json> {
    const hadRun = this.#runId !== null;
    this.#state = this.#state === 'FAULTED' ? 'FAULTED' : 'CLOSING';
    this.#closeAdmission();
    // Strong barrier: acknowledge only once no signing is in flight. A hang means the controller must kill us.
    if (this.#service && !(await this.#service.drain(this.#drainMs))) return this.#error(requestId, 'FAULTED');
    if (this.#server?.listening) await new Promise<void>((resolve) => this.#server!.close(() => resolve()));
    if (hadRun) { this.#runClosed = true; this.#fault = this.#fault ?? reason; }
    this.#state = 'FENCED';
    return this.#ok(requestId, 'FENCED', {});
  }

  #ok(requestId: string, result: string, data: Json): Json {
    const reply = { version: 1, request_id: requestId, state: this.#state, run_id: this.#runId, config_digest: this.#digest,
      incarnation: this.incarnation, ok: true, result, data };
    validateControlResponse(reply);
    return reply;
  }
  #error(requestId: string, result: ControlErrorResult): Json {
    const reply = { version: 1, request_id: requestId, state: this.#state, run_id: this.#runId, config_digest: this.#digest,
      incarnation: this.incarnation, ok: false, result, data: {} };
    validateControlResponse(reply);
    return reply;
  }

  /** REPORT payload: fixed allowlisted counters only. */
  report(requestId: string): Json {
    return this.#ok(requestId, 'REPORT', {
      counters: { ...(this.#service?.counters ?? { issuance_successes: 0, issuance_failures: 0 }) },
      measurements: [], same_source_observed: null, origin_counts_available: false, worker_verification_attempts: [],
    });
  }
}
