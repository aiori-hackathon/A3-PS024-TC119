// A client's own plaintext vouchers, held in memory only. Received via the bounded sealed provisioning protocol;
// each voucher is taken (removed) before use, so it can be offered at most once. Nothing here can enumerate or export.
import { inspect } from 'node:util';
import { decodeBase64Url } from '../../../../contracts/lib/index.ts';
import { SealedBatchSet, type Batch } from '../inventory.ts';

export class ClientVouchers {
  readonly #set: SealedBatchSet<Uint8Array>;
  constructor(maxTotal: number) {
    this.#set = new SealedBatchSet<Uint8Array>(maxTotal, (item) => ({ key: item, value: decodeBase64Url(item, 32, false) }));
  }
  get sealed(): boolean { return this.#set.sealed; }
  get remaining(): number { return this.#set.remaining; }
  get receivedTotal(): number { return this.#set.receivedTotal; }
  provision(batch: Batch) { return this.#set.provision(batch); }
  lock(): void { this.#set.lock(); }
  /** Removes and returns the oldest voucher, or undefined when none is left. */
  take(): Uint8Array | undefined { return this.#set.takeNext(); }
  clear(): void { this.#set.clear(); }
  toJSON(): string { return '[ClientVouchers]'; }
  [inspect.custom](): string { return `ClientVouchers { remaining: ${this.remaining} }`; }
}
