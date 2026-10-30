import {
  ContractError, configurationDigest, epochBounds, parseClaimReply, parseSnapshotReply,
  validateManifest, type Manifest,
} from '../../../contracts/lib/index.ts';
import { REPLAY_SCRIPTS } from './replay-scripts.ts';

/** Trusted internal transport boundary; never selected by an HTTP request or environment flag. */
export interface ReplayConnection {
  connect(): Promise<void>;
  call(command: string, ...args: (string | number)[]): Promise<unknown>;
  onLoss(handler: () => void): void;
  close(): void;
}
export type ReplayFault = 'dependency-lost' | 'unsafe-state' | 'clock-unsafe' | 'configuration-mismatch';
const unavailable = Object.freeze({ kind: 'unavailable' } as const);
const busy = Object.freeze({ kind: 'busy' } as const);
type NotAvailable = typeof unavailable | typeof busy;
export type ReplaySnapshot = NotAvailable | {
  kind: 'snapshot'; reply: readonly unknown[]; now_ms: number; epoch: number; start_ms: number; end_ms: number;
};
export type ReplayClaim = NotAvailable | { kind: 'claimed'; expiry_ms: number } |
  { kind: 'rejected'; reason: 'token-expired' | 'token-already-redeemed' };
type Slot = { connection: ReplayConnection; busy: boolean };
const policyFields = ['schema_version', 'run_id', 'token_type', 'token_key_id', 'config_digest', 'run_start_ms', 'epoch_ms', 'guard_ms'];
const clockFields = ['run_id', 'last_now_ms', 'highest_epoch', 'closed'];

/** One worker's bounded replay pool. A claimed result still requires a live lease before forwarding. */
export class ReplayStore {
  readonly #manifest: Manifest;
  readonly #identity: readonly string[];
  readonly #slots: Slot[];
  readonly #onFault: (reason: ReplayFault) => void;
  readonly #abort = new AbortController();
  #state: 'preparing' | 'ready' | 'closed' = 'preparing';
  #fault: ReplayFault | null = null;

  private constructor(manifest: Manifest, connections: ReplayConnection[], onFault: (reason: ReplayFault) => void) {
    this.#manifest = manifest;
    this.#identity = [manifest.run_id, manifest.token_key_id, configurationDigest(manifest)];
    this.#slots = connections.map(connection => ({ connection, busy: false }));
    this.#onFault = onFault;
    for (const { connection } of this.#slots) connection.onLoss(() => this.#fail('dependency-lost'));
  }

  /** Call only while the run is fenced, before ANY worker can claim. No same-run recovery. */
  static async prepare(configuration: unknown, connections: ReplayConnection[], onFault: (reason: ReplayFault) => void): Promise<ReplayStore> {
    let manifest: Manifest;
    try {
      manifest = validateManifest(structuredClone(configuration));
      if (manifest.snapshot_script_sha1 !== REPLAY_SCRIPTS.snapshot.sha1 || manifest.claim_script_sha1 !== REPLAY_SCRIPTS.claim.sha1 ||
        connections.length !== manifest.limits.gateway.redis_connections_per_worker || new Set(connections).size !== connections.length) {
        throw Error('configuration');
      }
    } catch {
      for (const connection of connections) { try { connection.close(); } catch { /* best effort before readiness */ } }
      throw new ContractError('replay-configuration-invalid');
    }
    const store = new ReplayStore(manifest, connections, onFault);
    try {
      await Promise.all(store.#slots.map(async slot => {
        await store.#bounded(() => slot.connection.connect(), manifest.limits.gateway.redis_connect_timeout_ms);
        // Read known fields only, after checking bounded cardinality. No HGETALL.
        for (const [key, fields, expected] of [
          ['pp:policy', policyFields, ['1', manifest.run_id, String(manifest.token_type), manifest.token_key_id,
            store.#identity[2], String(manifest.run_start_ms), String(manifest.epoch_ms), String(manifest.guard_ms)]],
          ['pp:clock', clockFields, [manifest.run_id, String(manifest.run_start_ms), '0', '0']],
        ] as const) {
          if (await store.#read(slot, 'TYPE', key) !== 'hash' || await store.#read(slot, 'PTTL', key) !== -1 ||
            await store.#read(slot, 'HLEN', key) !== fields.length) throw Error('guard');
          const values = await store.#read(slot, 'HMGET', key, ...fields);
          if (!Array.isArray(values) || values.length !== expected.length || values.some((v, i) => v !== expected[i])) throw Error('policy');
        }
        const scripts = await store.#read(slot, 'SCRIPT', 'EXISTS', manifest.snapshot_script_sha1, manifest.claim_script_sha1);
        if (!Array.isArray(scripts) || scripts.length !== 2 || scripts.some(v => v !== 1)) throw Error('scripts');
        const raw = await store.#read(slot, 'EVALSHA', manifest.snapshot_script_sha1, 2, 'pp:policy', 'pp:clock', ...store.#identity);
        if (!store.#snapshot(raw)) throw Error('snapshot');
      }));
      if (store.#state === 'closed') throw Error('closed');
      store.#state = 'ready';
      return store;
    } catch {
      store.#fail('unsafe-state');
      throw new ContractError('replay-preparation-failed');
    }
  }

  get status(): Readonly<{ state: 'preparing' | 'ready' | 'closed'; fault: ReplayFault | null }> {
    return Object.freeze({ state: this.#state, fault: this.#fault });
  }
  get signal(): AbortSignal { return this.#abort.signal; }
  get binding() { return Object.freeze({ run_id: this.#manifest.run_id, config_digest: this.#identity[2]! }); }

  /** Terminal local fence; never QUIT/reconnect/reinitialize. Suppresses late successes. */
  close(): void {
    this.#state = 'closed';
    for (const { connection } of this.#slots) { try { connection.close(); } catch { /* already closed locally */ } }
    this.#abort.abort();
  }

  #fail(reason: ReplayFault): void {
    if (this.#state === 'closed') return;
    this.#fault = reason;
    this.close();
    try { this.#onFault(reason); } catch { /* latch and disconnect precede external notification */ }
  }

  async #bounded<T>(operation: () => Promise<T>, ms: number): Promise<T> {
    if (this.status.state === 'closed') throw Error('closed');
    const deadline = performance.now() + ms;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => { this.#fail('dependency-lost'); reject(Error('deadline')); }, ms);
      });
      const value = await Promise.race([operation(), timeout]);
      // Timer callbacks can run late: a late fulfilled promise is NOT success.
      if (this.#state === 'closed' || performance.now() >= deadline) throw Error('deadline');
      return value;
    } catch {
      this.#fail('dependency-lost');
      throw new ContractError('replay-unavailable');
    } finally { clearTimeout(timer); }
  }

  #read(slot: Slot, command: string, ...args: (string | number)[]): Promise<unknown> {
    return this.#bounded(() => slot.connection.call(command, ...args), this.#manifest.limits.gateway.redis_command_timeout_ms);
  }

  #snapshot(raw: unknown): Exclude<ReplaySnapshot, NotAvailable> | null {
    const value = parseSnapshotReply(raw, this.#manifest);
    if (value.tag !== 'SNAPSHOT') {
      this.#fail(value.tag === 'CLOCK_UNSAFE' ? 'clock-unsafe' : 'unsafe-state');
      return null;
    }
    return { kind: 'snapshot', reply: Object.freeze([...(raw as unknown[])]), now_ms: value.now_ms!,
      epoch: value.epoch!, start_ms: value.start_ms!, end_ms: value.end_ms! };
  }

  async #run<T>(operation: (slot: Slot) => Promise<T>): Promise<T | NotAvailable> {
    if (this.#state !== 'ready') return unavailable;
    const slot = this.#slots.find(s => !s.busy);
    if (!slot) return busy; // No hidden FIFO/offline queue; enclosing flow admission owns waiting.
    slot.busy = true;
    try {
      const result = await operation(slot);
      return this.#state === 'ready' ? result : unavailable;
    } catch {
      this.#fail('unsafe-state');
      return unavailable;
    } finally { slot.busy = false; }
  }

  snapshot(): Promise<ReplaySnapshot> {
    return this.#run(async slot => this.#snapshot(await this.#read(slot, 'EVALSHA',
      this.#manifest.snapshot_script_sha1, 2, 'pp:policy', 'pp:clock', ...this.#identity)) ?? unavailable);
  }

  claim(candidate: unknown): Promise<ReplayClaim> {
    // Own primitive values before the first await; do not retain caller-owned objects.
    let epoch: number, digest: string, expiry: number;
    try {
      if (!candidate || typeof candidate !== 'object') throw Error('candidate');
      const { kind, epoch: e, spend_id: d } = candidate as { kind?: unknown; epoch?: unknown; spend_id?: unknown };
      if (kind !== 'claim-candidate' || typeof e !== 'number' || !Number.isSafeInteger(e) ||
        e < 0 || Object.is(e, -0) || typeof d !== 'string' || !/^[0-9a-f]{64}$/.test(d)) throw Error('candidate');
      epoch = e; digest = d;
      expiry = epochBounds(this.#manifest, epoch).end_ms + this.#manifest.guard_ms;
      if (!Number.isSafeInteger(expiry)) throw Error('expiry');
    } catch {
      this.#fail('unsafe-state');
      return Promise.resolve(unavailable);
    }
    return this.#run(async slot => {
      const raw = await this.#read(slot, 'EVALSHA', this.#manifest.claim_script_sha1, 3,
        'pp:policy', 'pp:clock', `pp:spent:${digest}`, ...this.#identity, String(epoch), digest);
      const value = parseClaimReply(raw, expiry);
      switch (value.tag) {
        case 'CLAIMED': return { kind: 'claimed', expiry_ms: value.expiry_ms! } as const;
        case 'ALREADY_SPENT': return { kind: 'rejected', reason: 'token-already-redeemed' } as const;
        case 'EPOCH_CLOSED': return { kind: 'rejected', reason: 'token-expired' } as const;
        default: this.#fail(value.tag === 'CLOCK_UNSAFE' ? 'clock-unsafe' : 'unsafe-state'); return unavailable;
      }
    });
  }
}
