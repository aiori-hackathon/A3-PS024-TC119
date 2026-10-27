import { randomBytes } from 'node:crypto';
import { ContractError, configurationDigest, validateControlResponse, validateManifest, type Manifest } from '../contracts/lib/index.ts';

export const RESET_ROLES = Object.freeze(['gateway', 'issuer', 'origin', 'client-A', 'client-B', 'client-C', 'client-D', 'client-E'] as const);
export type ResetRole = typeof RESET_ROLES[number];
/** instance_id pins a container ID or a creation-bound process identity; never a service name or reusable PID. */
export type ResetTarget = Readonly<{ role: ResetRole; incarnation: string; instance_id: string }>;
export type OldGeneration = { manifest: unknown; redis_instance_id: string; participants: readonly ResetTarget[] };
export interface ResetAdapters {
  fence(target: ResetTarget, request: Readonly<Record<string, unknown>>, signal: AbortSignal): Promise<unknown>;
  terminate(target: ResetTarget, signal: AbortSignal): Promise<unknown>;
  reportOrigin(target: ResetTarget, request: Readonly<Record<string, unknown>>, signal: AbortSignal): Promise<unknown>;
  discardRedis(instanceId: string, signal: AbortSignal): Promise<unknown>;
}
export interface ResetRuntime { nowNs(): bigint; schedule(ms: number, callback: () => void): () => void }
const runtime: ResetRuntime = { nowNs: () => process.hrtime.bigint(), schedule(ms, callback) {
  const timer = setTimeout(callback, ms); return () => clearTimeout(timer);
} };
declare const proof: unique symbol;
export type ResetReceipt = Readonly<{ [proof]: true }>;
type Counts = Readonly<{ protected_requests_received: number; generation_mismatches: number; resources_served: number }>;
type Outcome = Readonly<{ role: ResetRole; method: 'fenced' | 'terminated'; counts: Counts | null }>;
const id32 = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{32}$/.test(v);
const id64 = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const safe = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;

/** Controller safety utility, not a Docker driver or permission to enable a new run.
 * Adapters are trusted to target immutable old instances and prove descendant exits honestly.
 */
export class ResetBarrier {
  readonly #manifest: Manifest;
  readonly #digest: string;
  readonly #redis: string;
  readonly #targets: readonly ResetTarget[];
  readonly #adapters: ResetAdapters;
  readonly #runtime: ResetRuntime;
  readonly #receipts = new WeakMap<object, { used: boolean }>();
  #state: 'prepared' | 'fencing' | 'fenced' | 'blocked' | 'discarding' | 'discarded' | 'uncertain' = 'prepared';
  #fencing: Promise<ResetReceipt> | null = null;
  #lastNow = 0n;
  #clockUnsafe = false;
  #outcomes: readonly Outcome[] = [];

  private constructor(manifest: Manifest, redis: string, targets: ResetTarget[], adapters: ResetAdapters, clock: ResetRuntime) {
    this.#manifest = manifest; this.#digest = configurationDigest(manifest); this.#redis = redis;
    this.#targets = Object.freeze(targets); this.#adapters = adapters; this.#runtime = clock;
  }
  static prepare(generation: OldGeneration, adapters: ResetAdapters, clock: ResetRuntime = runtime): ResetBarrier {
    try {
      const manifest = validateManifest(structuredClone(generation.manifest));
      const targets = structuredClone(generation.participants).map(target => Object.freeze(target));
      if (!id64(generation.redis_instance_id) || targets.length !== RESET_ROLES.length ||
        targets.some(target => Object.keys(target).sort().join(',') !== 'incarnation,instance_id,role' ||
          !RESET_ROLES.includes(target.role) || !id32(target.incarnation) || !id64(target.instance_id) || target.instance_id === generation.redis_instance_id) ||
        new Set(targets.map(t => t.role)).size !== RESET_ROLES.length || new Set(targets.map(t => t.incarnation)).size !== targets.length ||
        new Set(targets.map(t => t.instance_id)).size !== targets.length) throw Error();
      for (const name of ['fence', 'terminate', 'reportOrigin', 'discardRedis'] as const) if (typeof adapters[name] !== 'function') throw Error();
      // Capture adapter functions before awaits; mutating the caller's adapter table cannot retarget a reset.
      const owned = Object.freeze({ fence: adapters.fence.bind(adapters), terminate: adapters.terminate.bind(adapters),
        reportOrigin: adapters.reportOrigin.bind(adapters), discardRedis: adapters.discardRedis.bind(adapters) });
      return new ResetBarrier(manifest, generation.redis_instance_id, targets, owned, clock);
    } catch { throw new ContractError('reset-configuration-invalid'); }
  }
  get status() {
    const origin = this.#outcomes.find(o => o.role === 'origin');
    return Object.freeze({ state: this.#state, run_id: this.#manifest.run_id, config_digest: this.#digest,
      participants_stopped: this.#outcomes.length, origin_counts_available: !!origin?.counts,
      origin_counts: origin?.counts ?? null, roles: Object.freeze(this.#outcomes.map(o => Object.freeze({ role: o.role, method: o.method }))) });
  }
  #now(): bigint {
    try {
      const now = this.#runtime.nowNs();
      if (this.#clockUnsafe || typeof now !== 'bigint' || now < this.#lastNow || now < 0n || now > (1n << 64n) - 1n) throw Error();
      this.#lastNow = now; return now;
    } catch { this.#clockUnsafe = true; throw new ContractError('reset-clock-unsafe'); }
  }
  #bounded<T>(operation: (signal: AbortSignal) => Promise<T>): Promise<T> {
    return new Promise((resolve, reject) => {
      const abort = new AbortController(); let settled = false, cancel: (() => void) | undefined;
      const finish = (ok: boolean, value?: T) => {
        if (settled) return; settled = true;
        try { cancel?.(); } catch { ok = false; }
        if (!ok) abort.abort();
        if (ok) resolve(value!); else reject(new ContractError('reset-operation-unconfirmed'));
      };
      let deadline: bigint;
      try {
        deadline = this.#now() + 10000000000n;
        const arm = () => {
          try {
            const now = this.#now();
            if (now >= deadline) { finish(false); return; }
            cancel = this.#runtime.schedule(Number((deadline - now + 999999n) / 1000000n), arm);
          } catch { finish(false); }
        };
        arm();
        if (settled) return;
        Promise.resolve(operation(abort.signal)).then(value => {
          if (settled) return;
          try { finish(this.#now() < deadline, value); } catch { finish(false); }
        }, () => finish(false));
      } catch { finish(false); }
    });
  }
  #request(command: 'FENCE' | 'REPORT', target: ResetTarget): Readonly<Record<string, unknown>> {
    return Object.freeze({ version: 1, request_id: randomBytes(16).toString('hex'), command,
      run_id: this.#manifest.run_id, config_digest: this.#digest, target_incarnation: target.incarnation,
      payload: Object.freeze(command === 'FENCE' ? { reason: 'operator-stop' } : {}) });
  }
  #reply(raw: unknown, request: Readonly<Record<string, unknown>>, target: ResetTarget, result: string): Record<string, unknown> {
    const reply = structuredClone(raw) as Record<string, unknown>; validateControlResponse(reply);
    if (reply['request_id'] !== request['request_id'] || reply['incarnation'] !== target.incarnation ||
      reply['run_id'] !== this.#manifest.run_id || reply['config_digest'] !== this.#digest || reply['ok'] !== true ||
      reply['state'] !== 'FENCED' || reply['result'] !== result) throw Error();
    return reply;
  }
  async #stop(target: ResetTarget): Promise<Outcome> {
    const request = this.#request('FENCE', target);
    try {
      this.#reply(await this.#bounded(signal => this.#adapters.fence(target, request, signal)), request, target, 'FENCED');
    } catch {
      if (this.#clockUnsafe) {
        // Clock failure cannot authorize reset. Still attempt identity-bound emergency termination.
        try { Promise.resolve(this.#adapters.terminate(target, new AbortController().signal)).catch(() => {}); } catch { /* caller must escalate */ }
        throw Error();
      }
      const raw = await this.#bounded(signal => this.#adapters.terminate(target, signal));
      const exit = structuredClone(raw) as Record<string, unknown>;
      if (!exit || Object.keys(exit).sort().join(',') !== 'descendants_exited,exited,incarnation,instance_id,role' ||
        exit['role'] !== target.role || exit['incarnation'] !== target.incarnation || exit['instance_id'] !== target.instance_id ||
        exit['exited'] !== true || exit['descendants_exited'] !== true) throw Error();
      return Object.freeze({ role: target.role, method: 'terminated', counts: null });
    }
    let counts: Counts | null = null;
    if (target.role === 'origin') {
      try {
        const report = this.#request('REPORT', target);
        const reply = this.#reply(await this.#bounded(signal => this.#adapters.reportOrigin(target, report, signal)), report, target, 'REPORT');
        const data = reply['data'] as Record<string, unknown>, c = data['counters'] as Record<string, unknown>;
        const received = c['protected_requests_received'], mismatches = c['generation_mismatches'], served = c['resources_served'];
        if (data['origin_counts_available'] !== true || !safe(received) || !safe(mismatches) || !safe(served) || mismatches > received || served > received - mismatches) throw Error();
        counts = Object.freeze({ protected_requests_received: received, generation_mismatches: mismatches, resources_served: served });
      } catch { /* Safe teardown can proceed; evidence is unavailable, never invented zero. */ }
    }
    return Object.freeze({ role: target.role, method: 'fenced', counts });
  }
  fenceAll(): Promise<ResetReceipt> {
    if (this.#fencing) return this.#fencing;
    let resolve!: (receipt: ResetReceipt) => void, reject!: (error: Error) => void;
    this.#fencing = new Promise((done, failed) => { resolve = done; reject = failed; });
    this.#fencing.catch(() => {}); this.#state = 'fencing';
    Promise.allSettled(this.#targets.map(target => this.#stop(target))).then(results => {
      if (this.#clockUnsafe || results.some(result => result.status === 'rejected')) {
        this.#state = 'blocked'; reject(new ContractError('reset-barrier-unconfirmed')); return;
      }
      this.#outcomes = Object.freeze(results.map(result => (result as PromiseFulfilledResult<Outcome>).value));
      this.#state = 'fenced'; const receipt = Object.freeze({}) as ResetReceipt;
      this.#receipts.set(receipt, { used: false }); resolve(receipt);
    });
    return this.#fencing;
  }
  async discardOldRedis(receipt: ResetReceipt): Promise<void> {
    const proof = receipt && typeof receipt === 'object' ? this.#receipts.get(receipt) : undefined;
    if (!proof || proof.used || this.#state !== 'fenced') throw new ContractError('reset-receipt-invalid');
    proof.used = true; this.#state = 'discarding'; // Consume BEFORE any reentrant callback or await.
    try {
      const raw = await this.#bounded(signal => this.#adapters.discardRedis(this.#redis, signal));
      const result = structuredClone(raw) as Record<string, unknown>;
      if (!result || Object.keys(result).sort().join(',') !== 'exited,instance_id' || result['instance_id'] !== this.#redis || result['exited'] !== true) throw Error();
      this.#state = 'discarded';
    } catch { this.#state = 'uncertain'; throw new ContractError('reset-discard-unconfirmed'); }
  }
}
