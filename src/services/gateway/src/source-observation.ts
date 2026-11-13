import { createHmac } from 'node:crypto';
export type SourceSummary = { observations: number; consistent: boolean | null; tag: string | null };
/** Generation-scoped equality only. No address is retained. Tags never leave private worker IPC. */
export class SourceObservation {
  readonly #key: Buffer;
  #tag: string | null = null;
  #same = true;
  #unknown = false;
  #count = 0;
  constructor(key: string) {
    if (!/^[0-9a-f]{64}$/.test(key)) throw Error('source-observation-key');
    this.#key = Buffer.from(key, 'hex');
  }
  observe(address: string | undefined): void {
    if (this.#count >= 65535) { this.#unknown = true; return; }
    this.#count++;
    if (!address) { this.#unknown = true; return; }
    const tag = createHmac('sha256', this.#key).update(address).digest('hex');
    if (this.#tag === null) this.#tag = tag;
    else if (this.#tag !== tag) this.#same = false;
  }
  summary(): SourceSummary { return { observations: this.#count, consistent: !this.#same ? false : this.#unknown ? null : true, tag: this.#tag }; }
}
export function combineSources(summaries: readonly SourceSummary[]): { observations: number; same: boolean | null } {
  let observations = 0, tag: string | null = null, mismatch = false, unknown = false;
  for (const s of summaries) {
    if (!Number.isInteger(s.observations) || s.observations < 0 || s.observations > 65535 ||
      (s.tag !== null && !/^[0-9a-f]{64}$/.test(s.tag)) || ![null, true, false].includes(s.consistent)) throw Error('source-observation-invalid');
    observations += s.observations;
    if (s.observations === 0) continue;
    if (s.consistent === null || s.tag === null) unknown = true;
    if (s.consistent === false) mismatch = true;
    if (tag !== null && s.tag !== null && tag !== s.tag) mismatch = true;
    tag ??= s.tag;
  }
  return { observations, same: mismatch ? false : unknown || observations < 2 ? null : true };
}
