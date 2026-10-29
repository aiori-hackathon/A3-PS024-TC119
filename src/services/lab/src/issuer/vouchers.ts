// Issuer-side one-use voucher policy. Holds SHA-256 voucher digests only; plaintext vouchers never reach the issuer.
// A consumed digest is gone even if signing later fails or is uncertain: no reinsertion, no live refill.
import { SealedBatchSet, type Batch } from '../inventory.ts';

export type VoucherBatch = Batch;
const DIGEST = /^[0-9a-f]{64}$/;

export class VoucherStore {
  readonly #set: SealedBatchSet<true>;
  constructor(maxTotal: number) {
    this.#set = new SealedBatchSet<true>(maxTotal, (item) => {
      if (!DIGEST.test(item)) throw new Error('digest');
      return { key: item, value: true };
    });
  }
  get sealed(): boolean { return this.#set.sealed; }
  get receivedTotal(): number { return this.#set.receivedTotal; }
  get remaining(): number { return this.#set.remaining; }
  provision(batch: VoucherBatch) { return this.#set.provision(batch); }
  lock(): void { this.#set.lock(); }
  consume(digest: string): boolean { return this.#set.take(digest) === true; }
  clear(): void { this.#set.clear(); }
}
