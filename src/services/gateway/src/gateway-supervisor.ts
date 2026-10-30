import { randomBytes } from 'node:crypto';
import { configurationDigest, validateControlRequest, validateControlResponse, validateManifest, type Manifest } from '../../../contracts/lib/index.ts';
import { WorkerLease, monotonicRuntime, type LeaseRuntime, type WorkerCloseReason, type WorkerLeaseGrant } from './worker-lease.ts';

/** Private same-container worker channel. close resolves only after confirmed process exit. */
export interface SupervisorWorker {
  incarnation: string;
  prepare(manifest: Manifest, supervisor: string): Promise<void>;
  enable(grant: WorkerLeaseGrant): Promise<void>;
  listen(): Promise<void>;
  heartbeat(grant: WorkerLeaseGrant): Promise<void>;
  attempts(): Promise<number>;
  close(): Promise<void>;
}
export type WorkerFactory = (index: number, fault: (reason: WorkerCloseReason) => void) => Promise<SupervisorWorker>;
type State = 'FENCED' | 'PREPARED' | 'READY' | 'ENABLED' | 'CLOSING' | 'FAULTED';

/** One process incarnation, one immutable run. New runs require fresh processes after the external reset barrier. */
export class GatewaySupervisor {
  readonly incarnation = randomBytes(16).toString('hex');
  readonly #factory: WorkerFactory;
  readonly #runtime: LeaseRuntime;
  #manifest: Manifest | null = null;
  #digest: string | null = null;
  #state: State = 'FENCED';
  #lease: WorkerLease | null = null;
  #workers: SupervisorWorker[] = [];
  #closed = false;
  #faultReason: WorkerCloseReason | null = null;
  #busy = false;
  #initial: WorkerLeaseGrant | null = null;
  #lastSequence = 0;
  #preparation: Promise<void> = Promise.resolve();
  #drain: Promise<void> | null = null;

  constructor(factory: WorkerFactory, runtime: LeaseRuntime = monotonicRuntime) { this.#factory = factory; this.#runtime = runtime; }
  get status() {
    if (this.#state === 'ENABLED') this.#lease?.checkActive();
    return Object.freeze({ state: this.#state, run_id: this.#manifest?.run_id ?? null, config_digest: this.#digest,
      incarnation: this.incarnation, run_closed: this.#closed, fault: this.#faultReason,
      ready: !this.#closed && ['READY', 'ENABLED'].includes(this.#state) });
  }
  fault(reason: WorkerCloseReason): void {
    if (this.#closed) return;
    this.#faultReason = reason; this.#state = 'FAULTED'; void this.fence(reason);
  }
  #grant(worker: string, sequence: number, stamp: bigint): WorkerLeaseGrant {
    return { version: 1, run_id: this.#manifest!.run_id, config_digest: this.#digest!,
      supervisor_incarnation: this.incarnation, worker_incarnation: worker, sequence,
      issued_at_ns: String(stamp), expires_at_ns: String(stamp + 3000000000n) };
  }
  #live(): boolean { return !this.#closed && !!this.#lease?.checkActive() && !this.#closed; }
  #reply(id: string, ok: boolean, result: string, data: unknown = {}): Record<string, unknown> {
    const s = this.status;
    const reply = { version: 1, request_id: id, ok, result, state: s.state, run_id: s.run_id,
      config_digest: s.config_digest, incarnation: this.incarnation, data };
    validateControlResponse(reply); return reply;
  }
  async handle(raw: unknown): Promise<Record<string, unknown>> {
    let request: Record<string, unknown>;
    try { request = validateControlRequest(structuredClone(raw)); }
    catch {
      const id = (raw as { request_id?: unknown } | null)?.request_id;
      if (typeof id !== 'string' || !/^[0-9a-f]{32}$/.test(id)) throw new Error('control-message-invalid');
      return this.#reply(id, false, (raw as { version?: unknown })?.version !== 1 ? 'BAD_VERSION' : 'BAD_MESSAGE');
    }
    const id = request['request_id'] as string, command = request['command'] as string;
    const payload = request['payload'] as Record<string, unknown>;
    if (command === 'FENCE') {
      await this.fence(payload['reason'] as WorkerCloseReason);
      this.#state = 'FENCED'; return this.#reply(id, true, 'FENCED');
    }
    if (request['target_incarnation'] !== null && request['target_incarnation'] !== this.incarnation) return this.#reply(id, false, 'WRONG_INCARNATION');
    if (command === 'STATUS') {
      const s = this.status; return this.#reply(id, true, 'STATUS', { ready: s.ready, run_closed: s.run_closed, fault: s.fault });
    }
    if (request['target_incarnation'] !== this.incarnation) return this.#reply(id, false, 'WRONG_INCARNATION');
    if (command !== 'PREPARE_RUN' && request['run_id'] !== this.#manifest?.run_id) return this.#reply(id, false, 'WRONG_RUN');
    if (request['config_digest'] !== this.#digest) return this.#reply(id, false, 'WRONG_CONFIG');
    if (this.#closed) return this.#reply(id, false, 'FAULTED');
    if (this.#busy) return this.#reply(id, false, 'ILLEGAL_STATE');
    this.#busy = true;
    try {
      if (command === 'PREPARE_RUN') {
        if (payload['role'] !== 'gateway' || Object.keys(payload['role_config'] as object).length) return this.#reply(id, false, 'BAD_MESSAGE');
        if (this.#manifest || this.#state !== 'FENCED') return this.#reply(id, false, 'ILLEGAL_STATE');
        this.#manifest = validateManifest(payload['manifest']); this.#digest = configurationDigest(this.#manifest);
        this.#state = 'PREPARED';
        this.#lease = WorkerLease.prepare(this.#manifest, { worker_incarnation: this.incarnation,
          supervisor_incarnation: this.incarnation }, reason => { if (!this.#closed) this.fault(reason); }, this.#runtime);
        this.#preparation = this.#prepare();
        await this.#preparation;
        if (this.#closed) return this.#reply(id, false, 'FAULTED');
        return this.#reply(id, true, 'PREPARED');
      }
      if (command === 'CHECK_READY') {
        if (!['PREPARED', 'READY'].includes(this.#state) || this.#workers.length !== this.#manifest!.limits.gateway.workers || !this.#lease?.markReady()) return this.#reply(id, false, 'ILLEGAL_STATE');
        this.#state = 'READY'; return this.#reply(id, true, 'READY', { workers_ready: this.#workers.length });
      }
      if (command === 'ENABLE') {
        if (this.#state === 'ENABLED') {
          if (!this.#initial || !this.#lease?.enable(this.#initial) || !this.#live()) return this.#reply(id, false, 'FAULTED');
          return this.#reply(id, true, 'ENABLED', { workers_enabled: this.#workers.length });
        }
        if (this.#state !== 'READY') return this.#reply(id, false, 'ILLEGAL_STATE');
        const stamp = this.#runtime.nowNs(); this.#initial = this.#grant(this.incarnation, 0, stamp);
        if (!this.#lease?.enable(this.#initial)) throw Error();
        await Promise.all(this.#workers.map(worker => worker.enable(this.#grant(worker.incarnation, 0, stamp))));
        if (!this.#live()) throw Error();
        // No worker listener exists until EVERY configured worker acknowledged the original lease.
        await Promise.all(this.#workers.map(worker => worker.listen()));
        if (!this.#live()) throw Error();
        this.#state = 'ENABLED'; return this.#reply(id, true, 'ENABLED', { workers_enabled: this.#workers.length });
      }
      if (command === 'HEARTBEAT') {
        const sequence = payload['seq'] as number;
        if (this.#state !== 'ENABLED' || !this.#live()) return this.#reply(id, false, 'ILLEGAL_STATE');
        if (sequence <= this.#lastSequence) return this.#reply(id, false, 'ILLEGAL_STATE');
        const stamp = this.#runtime.nowNs();
        if (!this.#lease!.heartbeat(this.#grant(this.incarnation, sequence, stamp))) throw Error();
        this.#lastSequence = sequence;
        await Promise.all(this.#workers.map(worker => worker.heartbeat(this.#grant(worker.incarnation, sequence, stamp))));
        if (!this.#live()) throw Error();
        return this.#reply(id, true, 'HEARTBEAT_ACK', { seq: sequence });
      }
      if (command === 'REPORT') {
        const attempts = await Promise.all(this.#workers.map(worker => worker.attempts()));
        if (this.#closed || attempts.some(n => !Number.isSafeInteger(n) || n < 0) || !Number.isSafeInteger(attempts.reduce((a, b) => a + b, 0))) throw Error();
        return this.#reply(id, true, 'REPORT', { counters: { verification_attempts: attempts.reduce((a, b) => a + b, 0) },
          measurements: [], same_source_observed: null, origin_counts_available: false,
          worker_verification_attempts: attempts.map((n, i) => ({ worker_index: i, attempts: n })) });
      }
      return this.#reply(id, false, 'ILLEGAL_STATE');
    } catch {
      this.fault('dependency-lost'); return this.#reply(id, false, 'DEPENDENCY_UNAVAILABLE');
    } finally { this.#busy = false; }
  }
  async #prepare(): Promise<void> {
    const results = await Promise.allSettled(Array.from({ length: this.#manifest!.limits.gateway.workers }, async (_, index) => {
      const worker = await this.#factory(index, reason => this.fault(reason));
      this.#workers[index] = worker;
      if (this.#closed) { await worker.close(); throw Error(); }
      if (!/^[0-9a-f]{32}$/.test(worker.incarnation) || this.#workers.some(other => other !== worker && other.incarnation === worker.incarnation)) throw Error();
      await worker.prepare(this.#manifest!, this.incarnation);
      if (this.#closed) throw Error();
    }));
    if (results.some(result => result.status === 'rejected')) throw Error();
  }
  /** Gateway-local strong barrier: every owned worker has exited; external roles are controller duties. */
  fence(reason: WorkerCloseReason = 'operator-stop'): Promise<void> {
    if (this.#drain) return this.#drain;
    let resolve!: () => void, reject!: (error: Error) => void;
    this.#drain = new Promise<void>((done, failed) => { resolve = done; reject = failed; });
    this.#drain.catch(() => {}); this.#closed = true;
    if (!this.#faultReason) this.#state = 'CLOSING';
    this.#lease?.requestClose(reason);
    const closing = this.#workers.map(async worker => { await worker.close(); });
    Promise.allSettled([this.#preparation, ...closing]).then(async () => {
      const results = await Promise.allSettled(this.#workers.map(async worker => { await worker.close(); }));
      if (results.some(result => result.status === 'rejected')) throw Error();
      if (!this.#faultReason) this.#state = 'FENCED';
    }).then(resolve, () => reject(new Error('gateway-fence-failed')));
    return this.#drain;
  }
}
