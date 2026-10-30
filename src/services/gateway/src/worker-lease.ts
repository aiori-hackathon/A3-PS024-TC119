import { ContractError, PROTOCOL, configurationDigest, validateManifest, type Manifest } from '../../../contracts/lib/index.ts';

/** Gateway-internal IPC data, not the public controller HEARTBEAT payload.
 * Timestamps are original supervisor OS-monotonic nanoseconds, never worker-relative durations.
 */
export type WorkerLeaseGrant = {
  version: 1; run_id: string; config_digest: string; supervisor_incarnation: string; worker_incarnation: string;
  sequence: number; issued_at_ns: string; expires_at_ns: string;
};
export type WorkerCloseReason = 'operator-stop' | 'test-cleanup' | 'unsafe-state' | 'lease-expired' |
  'dependency-lost' | 'clock-unsafe' | 'process-exited' | 'control-lost' | 'configuration-mismatch';
export interface LeaseRuntime {
  nowNs(): bigint;
  schedule(afterMs: number, callback: () => void): () => void;
}
export const monotonicRuntime: LeaseRuntime = Object.freeze({
  nowNs: () => process.hrtime.bigint(),
  schedule(afterMs: number, callback: () => void) {
    const timer = setTimeout(callback, afterMs);
    timer.unref();
    return () => clearTimeout(timer);
  },
});
const MAX_NS = (1n << 64n) - 1n;
const ns = (value: unknown): bigint | null => {
  if (typeof value !== 'string' || value.length > 20 || !/^(0|[1-9][0-9]*)$/.test(value)) return null;
  const result = BigInt(value);
  return result <= MAX_NS ? result : null;
};
const isId = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value);
type Grant = { wire: WorkerLeaseGrant; issued: bigint; expiry: bigint };

/** One immutable prepared run in one worker. No reset/re-enable or strong FENCE acknowledgement.
 * Caller must complete real dependency readiness before markReady(), and an all-worker barrier before admission.
 */
export class WorkerLease {
  readonly #manifest: Manifest;
  readonly #digest: string;
  readonly #worker: string;
  readonly #supervisor: string;
  readonly #runtime: LeaseRuntime;
  readonly #onClose: (reason: WorkerCloseReason) => void;
  readonly #abort = new AbortController();
  readonly #duration: bigint;
  #state: 'PREPARED' | 'READY' | 'ENABLED' | 'CLOSING' | 'FAULTED' = 'PREPARED';
  #closed = false;
  #reason: WorkerCloseReason | null = null;
  #lastNow = 0n;
  #initial: Grant | null = null;
  #current: Grant | null = null;
  #cancelTimer: (() => void) | null = null;

  private constructor(manifest: Manifest, worker: string, supervisor: string,
    onClose: (reason: WorkerCloseReason) => void, runtime: LeaseRuntime) {
    this.#manifest = manifest; this.#digest = configurationDigest(manifest);
    this.#worker = worker; this.#supervisor = supervisor; this.#onClose = onClose; this.#runtime = runtime;
    this.#duration = BigInt(manifest.limits.gateway.controller_lease_ms) * 1000000n;
  }

  static prepare(configuration: unknown, identity: { worker_incarnation: string; supervisor_incarnation: string },
    onClose: (reason: WorkerCloseReason) => void, runtime: LeaseRuntime = monotonicRuntime): WorkerLease {
    try {
      const manifest = validateManifest(structuredClone(configuration));
      const worker = identity.worker_incarnation, supervisor = identity.supervisor_incarnation;
      if (!isId(worker) || !isId(supervisor)) throw Error('identity');
      return new WorkerLease(manifest, worker, supervisor, onClose, runtime);
    } catch { throw new ContractError('worker-configuration-invalid'); }
  }

  get signal(): AbortSignal { return this.#abort.signal; }
  get status() {
    return Object.freeze({ state: this.#state, run_closed: this.#closed, fault: this.#reason,
      run_id: this.#manifest.run_id, config_digest: this.#digest, incarnation: this.#worker });
  }

  #now(): bigint | null {
    if (this.#closed) return null;
    try {
      const now = this.#runtime.nowNs();
      if (typeof now !== 'bigint' || now < this.#lastNow || now < 0n || now > MAX_NS) throw Error('clock');
      this.#lastNow = now;
      return now;
    } catch { this.requestClose('clock-unsafe'); return null; }
  }

  /** Dependency readiness is supplied by the enclosing worker, never assumed by this helper. */
  markReady(): boolean {
    if (this.#closed || !['PREPARED', 'READY'].includes(this.#state) || this.#now() === null) return false;
    this.#state = 'READY'; return true;
  }

  #grant(raw: unknown): Grant | null {
    try {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).length !== 8) return null;
      const wire = structuredClone(raw) as WorkerLeaseGrant;
      if (wire.version !== 1 || wire.run_id !== this.#manifest.run_id || wire.config_digest !== this.#digest ||
        wire.worker_incarnation !== this.#worker || wire.supervisor_incarnation !== this.#supervisor ||
        !Number.isSafeInteger(wire.sequence) || wire.sequence < 0 || Object.is(wire.sequence, -0)) return null;
      const issued = ns(wire.issued_at_ns), expiry = ns(wire.expires_at_ns);
      if (issued === null || expiry === null || expiry - issued !== this.#duration) return null;
      return { wire: Object.freeze(wire), issued, expiry };
    } catch { return null; }
  }

  /** Synchronous check before admission, queue promotion and immediately before I/O, with no intervening await. */
  checkActive(): boolean {
    return this.#activeNow() !== null;
  }

  #activeNow(): bigint | null {
    if (this.#closed || this.#state !== 'ENABLED') return null;
    const now = this.#now();
    if (now === null) return null;
    if (!this.#current || now >= this.#current.expiry) { this.requestClose('lease-expired'); return null; }
    return now;
  }

  enable(raw: unknown): boolean {
    if (this.#closed) return false;
    if (this.#state === 'ENABLED') {
      if (!this.checkActive()) return false; // Existing expiry wins over ANY repeated ENABLE.
      const grant = this.#grant(raw), initial = this.#initial;
      return !!grant && !!initial && grant.wire.sequence === 0 && grant.issued === initial.issued && grant.expiry === initial.expiry && this.checkActive();
    }
    if (this.#state !== 'READY') return false;
    const grant = this.#grant(raw);
    if (this.#closed || this.#state !== 'READY') return false;
    const now = this.#now();
    if (now === null || !grant || grant.wire.sequence !== 0 || grant.issued > now) return false;
    if (now >= grant.expiry) { this.requestClose('lease-expired'); return false; }
    this.#initial = grant; this.#current = grant; this.#state = 'ENABLED';
    return this.#arm();
  }

  heartbeat(raw: unknown): boolean {
    if (!this.checkActive()) return false; // Do this BEFORE considering a newer grant.
    const grant = this.#grant(raw);
    const now = this.#activeNow(), current = this.#current!;
    if (now === null || !grant || grant.issued > now || grant.expiry <= now ||
      grant.wire.sequence <= current.wire.sequence || grant.issued <= current.issued || grant.expiry <= current.expiry) return false;
    this.#current = grant;
    return this.#arm();
  }

  #arm(): boolean {
    try {
      this.#cancelTimer?.(); this.#cancelTimer = null;
      const now = this.#now();
      if (now === null || !this.#current) return false;
      if (now >= this.#current.expiry) { this.requestClose('lease-expired'); return false; }
      const remainingMs = Number((this.#current.expiry - now + 999999n) / 1000000n);
      this.#cancelTimer = this.#runtime.schedule(remainingMs, () => {
        // A canceled/early callback must evaluate CURRENT state, not an obsolete deadline.
        if (this.checkActive()) this.#arm();
      });
      return !this.#closed;
    } catch { this.requestClose('unsafe-state'); return false; }
  }

  /** Local terminal cancellation only. The future lifecycle host must still drain/kill before FENCED. */
  requestClose(reason: WorkerCloseReason): void {
    if (this.#closed) return;
    const fixed = PROTOCOL.faults.includes(reason) ? reason : 'unsafe-state';
    this.#closed = true; this.#reason = fixed;
    this.#state = fixed === 'operator-stop' || fixed === 'test-cleanup' ? 'CLOSING' : 'FAULTED';
    try { this.#cancelTimer?.(); } catch { /* terminal regardless of cleanup errors */ }
    this.#cancelTimer = null;
    this.#abort.abort();
    try { this.#onClose(fixed); } catch { /* terminal latch precedes notification */ }
  }

  fence(): void { this.requestClose('operator-stop'); }
}
