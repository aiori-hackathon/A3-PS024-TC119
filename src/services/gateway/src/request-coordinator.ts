import { ContractError, PROTOCOL, configurationDigest, validateManifest, type Manifest } from '../../../contracts/lib/index.ts';
import { FlowAdmission, type FlowPermit } from './flow-admission.ts';
import { GatewayResponses, copyRawHeaders, parseAuthorization, type GatewayError, type HttpRejection } from './http-auth.ts';
import { TokenVerifier } from './token-verifier.ts';
import type { ReplayStore } from './replay-store.ts';
import type { FixedOrigin, OriginResult } from './fixed-origin.ts';
import type { WorkerLease } from './worker-lease.ts';

/** Trusted HTTP adapter view. The future listener must additionally enforce native framing/TLS/socket deadlines. */
export type RequestView = { method: string; target: string; rawHeaders: unknown; hasBody: boolean; signal: AbortSignal };
export type CoordinatorResponse = HttpRejection | Extract<OriginResult, { kind: 'response' | 'upstream-error' }>;
/** Resolve only after actual downstream write/abort cleanup. Never throw to request a second response. */
export type ResponseSink = (response: CoordinatorResponse, signal: AbortSignal) => Promise<void>;
type Replay = Pick<ReplayStore, 'binding' | 'status' | 'signal' | 'snapshot' | 'claim' | 'close'>;
type Origin = Pick<FixedOrigin, 'binding' | 'status' | 'forwardAfterClaim' | 'close'>;

function preflight(m: Manifest, method: string, target: string, fields: string[], hasBody: boolean): GatewayError | null {
  const headers = new Map<string, string[]>();
  for (let i = 0; i < fields.length; i += 2) {
    const name = fields[i]!.toLowerCase(), list = headers.get(name) ?? [];
    list.push(fields[i + 1]!); headers.set(name, list);
  }
  const hosts = headers.get('host');
  if (!hosts || hosts.length !== 1) return 'request-malformed';
  const host = hosts[0]!.toLowerCase();
  if (host !== m.origin_name && host !== `${m.origin_name}:443`) return 'authority-not-allowed';
  if (target !== '/resource') return 'resource-not-found';
  if (method !== 'GET') return 'method-not-allowed';
  const lengths = headers.get('content-length');
  if (typeof hasBody !== 'boolean' || hasBody || headers.has('transfer-encoding') || headers.has('expect') || headers.has('upgrade') ||
    headers.get('connection')?.some(v => v.split(',').some(item => item.trim().toLowerCase() === 'upgrade')) ||
    (lengths && (lengths.length !== 1 || lengths[0] !== '0'))) return 'request-malformed';
  return null;
}

/** Per-worker protected request pipeline, not a listener or all-worker lifecycle supervisor. */
export class RequestCoordinator {
  readonly #lease: WorkerLease;
  readonly #replay: Replay;
  readonly #origin: Origin;
  readonly #admission: FlowAdmission;
  readonly #responses: GatewayResponses;
  readonly #verifier: TokenVerifier;
  readonly #manifest: Manifest;
  readonly #onReplayClosed: () => void;
  #closed = false;
  #drain: Promise<void> | null = null;

  private constructor(m: Manifest, lease: WorkerLease, replay: Replay, origin: Origin, verifier: TokenVerifier) {
    this.#manifest = m; this.#lease = lease; this.#replay = replay; this.#origin = origin; this.#verifier = verifier;
    this.#admission = FlowAdmission.prepare(m, lease); this.#responses = GatewayResponses.prepare(m);
    this.#onReplayClosed = () => { lease.requestClose(replay.status.fault ?? 'dependency-lost'); void this.close(); };
    replay.signal.addEventListener('abort', this.#onReplayClosed, { once: true });
    if (replay.signal.aborted || replay.status.state !== 'ready') this.#onReplayClosed();
  }

  static async prepare(configuration: unknown, lease: WorkerLease, replay: Replay, origin: Origin): Promise<RequestCoordinator> {
    let m: Manifest;
    try {
      m = validateManifest(structuredClone(configuration));
      const digest = configurationDigest(m);
      for (const binding of [lease.status, replay.binding, origin.binding]) {
        if (binding.run_id !== m.run_id || binding.config_digest !== digest) throw Error('binding');
      }
      if (lease.status.state !== 'PREPARED' || replay.status.state !== 'ready' || replay.signal.aborted || origin.status.closed) throw Error('readiness');
    } catch { throw new ContractError('coordinator-configuration-invalid'); }
    const verifier = await TokenVerifier.prepare(m);
    const coordinator = new RequestCoordinator(m, lease, replay, origin, verifier);
    if (coordinator.#closed || origin.status.closed || lease.status.state !== 'PREPARED' || !lease.markReady()) {
      await coordinator.close(); throw new ContractError('coordinator-preparation-failed');
    }
    return coordinator;
  }

  get status() { return this.#admission.status; }
  #fault(): void { this.#lease.requestClose('unsafe-state'); void this.close(); }
  #live(permit: FlowPermit): boolean { return !this.#closed && permit.checkActive() && !this.#closed; }

  async handle(view: RequestView, deliver: ResponseSink): Promise<void> {
    // Bounded, owned primitives before first await: callers cannot alter queued requests.
    const method = view.method, target = view.target, hasBody = view.hasBody, client = view.signal;
    const fields = copyRawHeaders(view.rawHeaders);
    const preflightError = fields ? preflight(this.#manifest, method, target, fields, hasBody) : 'request-malformed';
    let permit: FlowPermit | null = null, delivered = false;
    const send = async (response: CoordinatorResponse) => {
      if (delivered || client.aborted) return;
      if ((response.status === 200 || response.status === 401) && (!permit || !this.#live(permit))) response = this.#responses.rejection('authorization-unavailable');
      delivered = true; // A failed/partial sink must never cause a second response.
      await deliver(response, permit?.signal ?? client);
    };
    const unavailable = () => this.#responses.rejection('authorization-unavailable');
    const inactive = async () => { if (!client.aborted) await send(unavailable()); };
    const rejection = async (reason: GatewayError) => {
      if (!permit || !this.#live(permit)) { await inactive(); return; }
      if (PROTOCOL.gateway_results[reason] !== 401) { await send(this.#responses.rejection(reason)); return; }
      // Every FINAL 401 gets a NEW snapshot, never the context-check snapshot.
      const snapshot = await this.#replay.snapshot();
      if (!this.#live(permit)) { await inactive(); return; }
      if (snapshot.kind !== 'snapshot') {
        if (snapshot.kind === 'unavailable') this.#fault();
        await send(unavailable()); return;
      }
      await send(this.#responses.rejection(reason, snapshot.reply));
    };
    try {
      if (this.#closed || !this.#lease.checkActive()) { await inactive(); return; }
      const admission = await this.#admission.acquire(client);
      if (admission.kind === 'canceled') return;
      if (admission.kind === 'rejected') { await send(this.#responses.rejection(admission.reason)); return; }
      permit = admission.permit;
      if (!this.#live(permit)) { await inactive(); return; }
      if (preflightError) { await rejection(preflightError); return; }
      const auth = parseAuthorization(fields); fields!.length = 0;
      if (auth.kind === 'missing') { await rejection('token-required'); return; }
      if (auth.kind === 'rejected') { await rejection(auth.reason); return; }
      const verification = this.#verifier.verifySignature(auth.wire);
      auth.wire.fill(0); // Verifier owns its standalone copy before its first await.
      const signature = await verification;
      if (!this.#live(permit)) { await inactive(); return; }
      if (signature.kind === 'rejected') {
        if (signature.reason === 'authorization-unavailable') this.#fault();
        await rejection(signature.reason); return;
      }
      const snapshot = await this.#replay.snapshot();
      if (!this.#live(permit)) { await inactive(); return; }
      if (snapshot.kind !== 'snapshot') {
        if (snapshot.kind === 'unavailable') this.#fault();
        await rejection(snapshot.kind === 'busy' ? 'gateway-busy' : 'authorization-unavailable'); return;
      }
      const candidate = this.#verifier.checkContext(signature.receipt, snapshot.epoch);
      if (candidate.kind === 'rejected') {
        if (candidate.reason === 'authorization-unavailable') this.#fault();
        await rejection(candidate.reason); return;
      }
      if (!this.#live(permit)) { await inactive(); return; }
      const claim = await this.#replay.claim(candidate);
      if (!this.#live(permit)) { await inactive(); return; }
      if (claim.kind !== 'claimed') {
        if (claim.kind === 'unavailable') this.#fault();
        await rejection(claim.kind === 'rejected' ? claim.reason : claim.kind === 'busy' ? 'gateway-busy' : 'authorization-unavailable'); return;
      }
      if (!this.#live(permit)) { await inactive(); return; }
      const result = await this.#origin.forwardAfterClaim(permit);
      if (!this.#live(permit)) { await inactive(); return; }
      if (result.kind === 'response' || result.kind === 'upstream-error') await send(result);
      else if (result.kind !== 'canceled') {
        if (result.kind === 'unavailable') this.#fault();
        await rejection(result.kind === 'busy' ? 'gateway-busy' : 'authorization-unavailable');
      }
    } catch {
      if (!delivered) { this.#fault(); try { await inactive(); } catch { /* one attempted response only */ } }
    } finally {
      fields?.fill('');
      permit?.release(); // All awaited crypto/Redis/origin AND actual downstream cleanup have settled.
    }
  }

  /** Local flow/pool drainage only. The future listener/supervisor must prove the complete strong barrier. */
  close(): Promise<void> {
    if (!this.#drain) {
      // Publish the single drain promise BEFORE invoking any reentrant shutdown hooks.
      let resolve!: () => void, reject!: (error: Error) => void;
      this.#drain = new Promise<void>((done, failed) => { resolve = done; reject = failed; });
      this.#drain.catch(() => {}); // Internal fault callbacks may initiate closure without awaiting it.
      this.#closed = true;
      let failed = false;
      try { this.#lease.fence(); } catch { failed = true; }
      try {
        this.#replay.signal.removeEventListener('abort', this.#onReplayClosed);
        if (this.#replay.status.state !== 'closed') this.#replay.close();
      } catch { failed = true; }
      let origin: Promise<void> = Promise.resolve();
      try { origin = this.#origin.close(); } catch { failed = true; }
      const admission = this.#admission.close();
      Promise.allSettled([origin, admission]).then(results => {
        if (failed || results.some(result => result.status === 'rejected')) reject(new ContractError('coordinator-close-failed'));
        else resolve();
      });
    }
    return this.#drain;
  }
}
