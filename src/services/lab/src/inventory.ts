// Bounded, ordered, duplicate-checked, sealed provisioning shared by the issuer's voucher digests and each client's
// plaintext vouchers. Receiver-side state validation: schema checks alone do not provide any of this.
// No refill: once sealed, and after lock(), nothing can be added. Failed frames change nothing.
import { PROTOCOL } from '../../../contracts/lib/index.ts';
import { LabError } from './errors.ts';

export type Batch = { batch_id: string; batch_index: number; expected_total: number; final_batch: boolean; items: string[] };
export type Normalized<V> = { key: string; value: V };

export class SealedBatchSet<V> {
  readonly #pool = new Map<string, V>();
  readonly #seen = new Set<string>();
  readonly #maxTotal: number;
  readonly #normalize: (item: string) => Normalized<V>;
  #batchId: string | null = null;
  #expectedTotal = 0;
  #nextIndex = 0;
  #sealed = false;
  #locked = false;

  constructor(maxTotal: number, normalize: (item: string) => Normalized<V>) {
    if (!Number.isSafeInteger(maxTotal) || maxTotal < 1 || maxTotal > PROTOCOL.client_profiles.benchmark.inventory_max) throw new LabError('BAD_MESSAGE');
    this.#maxTotal = maxTotal;
    this.#normalize = normalize;
  }
  get sealed(): boolean { return this.#sealed; }
  get receivedTotal(): number { return this.#seen.size; }
  get remaining(): number { return this.#pool.size; }

  provision(batch: Batch): { received_total: number; sealed: boolean } {
    if (this.#locked || this.#sealed) throw new LabError('ILLEGAL_STATE');
    if (batch.items.length > PROTOCOL.provision_batch_max || batch.batch_index !== this.#nextIndex) throw new LabError('BAD_MESSAGE');
    if (batch.expected_total < 1 || batch.expected_total > this.#maxTotal) throw new LabError('BAD_MESSAGE');
    if (this.#nextIndex === 0) { this.#batchId = batch.batch_id; this.#expectedTotal = batch.expected_total; }
    else if (batch.batch_id !== this.#batchId || batch.expected_total !== this.#expectedTotal) throw new LabError('BAD_MESSAGE');
    const fresh = new Map<string, V>();
    for (const item of batch.items) {
      let n: Normalized<V>;
      try { n = this.#normalize(item); } catch { throw new LabError('BAD_MESSAGE'); }
      if (this.#seen.has(n.key) || fresh.has(n.key)) throw new LabError('BAD_MESSAGE');
      fresh.set(n.key, n.value);
    }
    const total = this.#seen.size + fresh.size;
    if (total > this.#expectedTotal || (batch.final_batch && total !== this.#expectedTotal)) throw new LabError('BAD_MESSAGE');
    for (const [k, v] of fresh) { this.#seen.add(k); this.#pool.set(k, v); }
    this.#nextIndex += 1;
    if (batch.final_batch) this.#sealed = true;
    return { received_total: this.#seen.size, sealed: this.#sealed };
  }
  /** At ENABLE. Requires the seal; provisioning can never resume. */
  lock(): void { if (!this.#sealed) throw new LabError('ILLEGAL_STATE'); this.#locked = true; }
  /** Atomic removal by key (synchronous, so at most one caller wins). Nothing is spendable before lock(). */
  take(key: string): V | undefined {
    if (!this.#locked) return undefined;
    const v = this.#pool.get(key);
    if (v !== undefined) this.#pool.delete(key);
    return v;
  }
  /** Atomic removal of the oldest remaining item. */
  takeNext(): V | undefined {
    if (!this.#locked) return undefined;
    const first = this.#pool.entries().next();
    if (first.done) return undefined;
    this.#pool.delete(first.value[0]);
    return first.value[1];
  }
  clear(): void { this.#pool.clear(); this.#locked = true; }
}
