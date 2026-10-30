import { ContractError, configurationDigest, validateManifest, type Manifest } from '../../../contracts/lib/index.ts';
import { monotonicRuntime, type LeaseRuntime, type WorkerLease } from './worker-lease.ts';

export type FlowPermit = Readonly<{ signal: AbortSignal; checkActive(): boolean; release(): void }>;
export type AdmissionResult = { kind: 'admitted'; permit: FlowPermit } |
  { kind: 'rejected'; reason: 'gateway-busy' | 'authorization-unavailable' } | { kind: 'canceled' };
const busy: AdmissionResult = Object.freeze({ kind: 'rejected', reason: 'gateway-busy' });
const unavailable: AdmissionResult = Object.freeze({ kind: 'rejected', reason: 'authorization-unavailable' });
const canceled: AdmissionResult = Object.freeze({ kind: 'canceled' });
type Entry = {
  phase: 'queued' | 'active' | 'done'; client: AbortSignal; abort: AbortController;
  deadline: bigint | null; cancelTimer: (() => void) | null; onAbort: () => void;
  resolve: (result: AdmissionResult) => void;
};

/** Per-worker flow capacity only; transport socket/header limits and strong FENCE remain separate. */
export class FlowAdmission {
  readonly #manifest: Manifest;
  readonly #lease: WorkerLease;
  readonly #runtime: LeaseRuntime;
  readonly #active = new Set<Entry>();
  #queue: Entry[] = [];
  #closed = false;
  #pumping = false;
  #lastNow = 0n;
  #drained: Promise<void> | null = null;
  #resolveDrained: (() => void) | null = null;
  readonly #onLeaseAbort: () => void;

  private constructor(manifest: Manifest, lease: WorkerLease, runtime: LeaseRuntime) {
    this.#manifest = manifest; this.#lease = lease; this.#runtime = runtime;
    this.#onLeaseAbort = () => { void this.close(); };
    lease.signal.addEventListener('abort', this.#onLeaseAbort, { once: true });
    if (lease.signal.aborted) void this.close();
  }

  static prepare(configuration: unknown, lease: WorkerLease, runtime: LeaseRuntime = monotonicRuntime): FlowAdmission {
    try {
      const manifest = validateManifest(structuredClone(configuration));
      if (lease.status.run_id !== manifest.run_id || lease.status.config_digest !== configurationDigest(manifest)) throw Error('identity');
      return new FlowAdmission(manifest, lease, runtime);
    } catch { throw new ContractError('admission-configuration-invalid'); }
  }

  get status() { return Object.freeze({ active: this.#active.size, queued: this.#queue.length, closed: this.#closed }); }

  #fail(): void {
    // Latch the worker too before cancellation listeners can run reentrantly.
    try { this.#lease.requestClose('unsafe-state'); }
    finally { void this.close(); }
  }

  #now(): bigint | null {
    try {
      const now = this.#runtime.nowNs();
      if (typeof now !== 'bigint' || now < this.#lastNow || now < 0n || now > (1n << 64n) - 1n) throw Error('clock');
      this.#lastNow = now; return now;
    } catch { this.#fail(); return null; }
  }

  #live(): boolean { return !this.#closed && this.#lease.checkActive() && !this.#closed; }

  #cleanup(entry: Entry): boolean {
    entry.client.removeEventListener('abort', entry.onAbort);
    try { entry.cancelTimer?.(); entry.cancelTimer = null; return true; }
    catch { entry.cancelTimer = null; this.#fail(); return false; }
  }

  #reject(entry: Entry, result: AdmissionResult): void {
    if (entry.phase !== 'queued') return;
    entry.phase = 'done';
    const index = this.#queue.indexOf(entry); if (index >= 0) this.#queue.splice(index, 1);
    const clean = this.#cleanup(entry); entry.deadline = null;
    entry.resolve(clean ? result : unavailable);
  }

  #arm(entry: Entry): void {
    if (entry.phase !== 'queued' || this.#closed) return;
    const now = this.#now(); if (now === null) return;
    if (now >= entry.deadline!) { this.#reject(entry, busy); this.#pump(); return; }
    try {
      entry.cancelTimer?.();
      const remainingMs = Number((entry.deadline! - now + 999999n) / 1000000n);
      entry.cancelTimer = this.#runtime.schedule(remainingMs, () => {
        if (entry.phase !== 'queued' || this.#closed) return;
        this.#arm(entry); // Early/canceled timers use the original deadline; never extend it.
      });
    } catch { this.#fail(); }
  }

  #grant(entry: Entry): void {
    // Keep the client listener attached through the queue-to-active transition.
    try { entry.cancelTimer?.(); entry.cancelTimer = null; } catch { this.#reject(entry, unavailable); this.#fail(); return; }
    if (!this.#live()) { this.#reject(entry, unavailable); return; }
    const now = this.#now();
    if (now === null) { this.#reject(entry, unavailable); return; }
    if (entry.client.aborted) { this.#reject(entry, canceled); return; }
    if (entry.deadline !== null && now >= entry.deadline) { this.#reject(entry, busy); return; }
    entry.phase = 'active'; entry.deadline = null;
    this.#active.add(entry); // Reserve BEFORE resolving the caller's promise.
    const permit: FlowPermit = Object.freeze({
      signal: entry.abort.signal,
      checkActive: () => entry.phase === 'active' && !entry.abort.signal.aborted && this.#live(),
      release: () => {
        if (entry.phase !== 'active') return;
        entry.phase = 'done'; this.#active.delete(entry); this.#cleanup(entry);
        entry.abort.abort();
        if (this.#closed && this.#active.size === 0) this.#resolveDrained?.();
        this.#pump();
      },
    });
    entry.resolve({ kind: 'admitted', permit });
  }

  #pump(): void {
    if (this.#pumping || this.#closed) return;
    this.#pumping = true;
    try {
      if (!this.#live()) return;
      const now = this.#now(); if (now === null) return;
      // Expired entries must free queue capacity even when active flows remain full.
      for (const entry of [...this.#queue]) {
        if (entry.client.aborted) this.#reject(entry, canceled);
        else if (now >= entry.deadline!) this.#reject(entry, busy);
      }
      while (!this.#closed && this.#queue.length && this.#active.size < this.#manifest.limits.gateway.active_flows_per_worker) {
        const entry = this.#queue.shift()!;
        this.#grant(entry);
      }
    } finally { this.#pumping = false; }
  }

  /** No credential/crypto/claim work happens here or while queued. */
  acquire(client: AbortSignal): Promise<AdmissionResult> {
    if (!this.#live()) return Promise.resolve(unavailable);
    if (client.aborted) return Promise.resolve(canceled);
    this.#pump();
    if (this.#closed) return Promise.resolve(unavailable);
    if (this.#queue.length >= this.#manifest.limits.gateway.queue_depth_per_worker) return Promise.resolve(busy);
    const now = this.#now(); if (now === null) return Promise.resolve(unavailable);
    return new Promise(resolve => {
      const entry: Entry = { phase: 'queued', client, abort: new AbortController(), deadline: null, cancelTimer: null, resolve,
        onAbort: () => {
          if (entry.phase === 'queued') { this.#reject(entry, canceled); this.#pump(); }
          else if (entry.phase === 'active') entry.abort.abort(); // Cancellation does NOT release capacity.
        },
      };
      client.addEventListener('abort', entry.onAbort, { once: true });
      if (client.aborted) { this.#reject(entry, canceled); return; }
      if (!this.#pumping && this.#queue.length === 0 && this.#active.size < this.#manifest.limits.gateway.active_flows_per_worker) this.#grant(entry);
      else {
        entry.deadline = now + BigInt(this.#manifest.limits.gateway.queue_wait_ms) * 1000000n;
        if (entry.deadline > (1n << 64n) - 1n) { this.#reject(entry, unavailable); this.#fail(); return; }
        this.#queue.push(entry); this.#arm(entry);
      }
    });
  }

  /** Terminal cancellation + wait for issued permits' actual cleanup. NOT a socket/process FENCE barrier. */
  close(): Promise<void> {
    if (!this.#drained) this.#drained = new Promise(resolve => { this.#resolveDrained = resolve; });
    if (!this.#closed) {
      this.#closed = true;
      this.#lease.signal.removeEventListener('abort', this.#onLeaseAbort);
      const queued = this.#queue; this.#queue = []; // Detach BEFORE invoking any cancellation callbacks.
      for (const entry of queued) this.#reject(entry, unavailable);
      for (const entry of this.#active) entry.abort.abort();
    }
    if (this.#active.size === 0) this.#resolveDrained?.();
    return this.#drained;
  }
}
