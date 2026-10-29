// Issuer-side one-use voucher policy. Holds SHA-256 voucher digests only; plaintext vouchers never reach the issuer.
// Provisioning is bounded, ordered, duplicate-checked and sealed before enable. There is no live refill and
// no reinsertion: a consumed digest is gone even if signing later fails or is uncertain.
import { PROTOCOL } from '../../../../contracts/lib/index.ts';
import { LabError } from '../errors.ts';

export type VoucherBatch = {
  batch_id: string; batch_index: number; expected_total: number; final_batch: boolean; items: string[];
};
const DIGEST = /^[0-9a-f]{64}$/;

export class VoucherStore {
  readonly #digests = new Set<string>();
  readonly #seen = new Set<string>();
  readonly #maxTotal: number;
  #batchId: string | null = null;
  #expectedTotal = 0;
  #nextIndex = 0;
  #sealed = false;
  #locked = false;

  /** maxTotal is the manifest's inventory_total; a caller-supplied total above it is refused. */
  constructor(maxTotal: number) {
    if (!Number.isSafeInteger(maxTotal) || maxTotal < 1 || maxTotal > PROTOCOL.client_profiles.benchmark.inventory_max) {
      throw new LabError('BAD_MESSAGE');
    }
    this.#maxTotal = maxTotal;
  }

  get sealed(): boolean { return this.#sealed; }
  get receivedTotal(): number { return this.#seen.size; }
  get remaining(): number { return this.#digests.size; }

  provision(batch: VoucherBatch): { received_total: number; sealed: boolean } {
    if (this.#locked) throw new LabError('ILLEGAL_STATE');
    if (this.#sealed) throw new LabError('ILLEGAL_STATE');
    if (batch.items.length > PROTOCOL.provision_batch_max) throw new LabError('BAD_MESSAGE');
    if (batch.batch_index !== this.#nextIndex) throw new LabError('BAD_MESSAGE');
    if (batch.expected_total < 1 || batch.expected_total > this.#maxTotal) throw new LabError('BAD_MESSAGE');
    if (this.#nextIndex === 0) {
      this.#batchId = batch.batch_id;
      this.#expectedTotal = batch.expected_total;
    } else if (batch.batch_id !== this.#batchId || batch.expected_total !== this.#expectedTotal) {
      throw new LabError('BAD_MESSAGE');
    }
    // Validate the whole frame before touching state so a bad frame changes nothing.
    const fresh = new Set<string>();
    for (const item of batch.items) {
      if (!DIGEST.test(item) || this.#seen.has(item) || fresh.has(item)) throw new LabError('BAD_MESSAGE');
      fresh.add(item);
    }
    if (this.#seen.size + fresh.size > this.#expectedTotal) throw new LabError('BAD_MESSAGE');
    if (batch.final_batch && this.#seen.size + fresh.size !== this.#expectedTotal) throw new LabError('BAD_MESSAGE');
    for (const item of fresh) { this.#seen.add(item); this.#digests.add(item); }
    this.#nextIndex += 1;
    if (batch.final_batch) this.#sealed = true;
    return { received_total: this.#seen.size, sealed: this.#sealed };
  }

  /** Called at ENABLE: provisioning can never resume for this store. */
  lock(): void {
    if (!this.#sealed) throw new LabError('ILLEGAL_STATE');
    this.#locked = true;
  }

  /** Synchronous, therefore atomic with respect to other requests: a digest can be consumed at most once. */
  consume(digest: string): boolean {
    if (!this.#locked) return false;
    return this.#digests.delete(digest);
  }

  /** Drops everything (fence/teardown). */
  clear(): void { this.#digests.clear(); this.#locked = true; }
}
