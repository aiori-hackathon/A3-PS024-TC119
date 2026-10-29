// Memory-only inventory of finalized tokens. Bounded by the manifest; take() removes, so a token leaves the
// inventory the moment it is handed out. No enumeration, no serialization, no persistence.
import { inspect } from 'node:util';
import { LabError } from '../errors.ts';

type Entry = { epoch: number; wire: Uint8Array };

export class TokenInventory {
  readonly #max: number;
  readonly #items: Entry[] = [];
  constructor(max: number) { this.#max = max; }
  get size(): number { return this.#items.length; }
  add(epoch: number, wire: Uint8Array): void {
    if (this.#items.length >= this.#max) throw new LabError('ILLEGAL_STATE');
    this.#items.push({ epoch, wire: Uint8Array.from(wire) });
  }
  /** Removes and returns the oldest token for the epoch, if any. */
  take(epoch: number): Uint8Array | undefined {
    const i = this.#items.findIndex((e) => e.epoch === epoch);
    return i < 0 ? undefined : this.#items.splice(i, 1)[0]!.wire;
  }
  clear(): void { for (const e of this.#items) e.wire.fill(0); this.#items.length = 0; }
  toJSON(): string { return '[TokenInventory]'; }
  [inspect.custom](): string { return `TokenInventory { size: ${this.size} }`; }
}
