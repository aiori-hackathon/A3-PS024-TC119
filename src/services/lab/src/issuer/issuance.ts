// Issuance endpoint semantics (plan section 4.2), independent of the HTTP transport.
// Order is fixed: content type, protocol validity (422, before any voucher is consumed), voucher (403),
// then signing. Framing errors (400/413/405) are the transport's job; see server.ts.
import { PROTOCOL, ContractError, decodeBase64Url, voucherDigest, sha256 } from '../../../../contracts/lib/index.ts';
import type { LabIssuer } from '../protocol.ts';
import { AdmissionGate } from './admission.ts';
import type { VoucherStore } from './vouchers.ts';

export const REQUEST_TYPE = 'application/private-token-request';
export const RESPONSE_TYPE = 'application/private-token-response';
export type IssueInput = { contentType: string | undefined; voucherHeaders: string[]; body: Uint8Array };
export type IssueOutput = { status: number; contentType: string; body: Uint8Array };

const fixed = (status: number, error: string): IssueOutput =>
  ({ status, contentType: 'application/json', body: new TextEncoder().encode(JSON.stringify({ error })) });

export class IssuanceService {
  readonly #issuer: LabIssuer;
  readonly #vouchers: VoucherStore;
  readonly #gate: AdmissionGate;
  readonly #truncatedKeyId: number;
  #open = false;
  #successes = 0;
  #failures = 0;

  constructor(issuer: LabIssuer, vouchers: VoucherStore, limits: typeof PROTOCOL.issuer_limits) {
    this.#issuer = issuer;
    this.#vouchers = vouchers;
    this.#gate = new AdmissionGate(limits.active_signings, limits.queue_depth, limits.queue_wait_ms);
    this.#truncatedKeyId = sha256(issuer.publicKeySpki).at(-1)!;
  }

  /** True when every in-flight signing has settled (fence barrier). */
  drain(timeoutMs: number): Promise<boolean> { return this.#gate.whenIdle(timeoutMs); }
  get counters() { return { issuance_successes: this.#successes, issuance_failures: this.#failures }; }
  /** Controller-owned. Closing also drops queued work; in-flight signings settle on their own. */
  setOpen(open: boolean): void { this.#open = open; if (!open) this.#gate.cancelQueued(); }

  async handle(input: IssueInput): Promise<IssueOutput> {
    if (!this.#open) return this.#fail(503, 'issuance-unavailable');
    if (input.contentType !== REQUEST_TYPE) return this.#fail(415, 'unsupported-media-type');
    const b = input.body;
    // Complete, bounded but protocol-invalid requests are 422 and consume nothing (RFC 9578 section 6.2).
    if (b.length !== PROTOCOL.request_bytes || ((b[0]! << 8) | b[1]!) !== PROTOCOL.token_type || b[2] !== this.#truncatedKeyId) {
      return this.#fail(422, 'issuance-request-invalid');
    }
    const release = await this.#gate.acquire();
    if (release === null) return this.#fail(503, 'issuance-busy');
    try {
      if (!this.#open) return this.#fail(503, 'issuance-unavailable');
      const voucher = this.#parseVoucher(input.voucherHeaders);
      // Atomic removal happens before signing starts and is never undone.
      if (voucher === null || !this.#vouchers.consume(voucherDigest(voucher))) return this.#fail(403, 'issuance-not-authorized');
      try {
        const response = await this.#issuer.sign(b);
        this.#successes += 1;
        return { status: 200, contentType: RESPONSE_TYPE, body: response };
      } catch {
        return this.#fail(500, 'issuance-failed');
      }
    } finally {
      release();
    }
  }

  #parseVoucher(values: string[]): Uint8Array | null {
    if (values.length !== 1) return null;
    try { return decodeBase64Url(values[0]!, 32, false); } catch (e) { if (e instanceof ContractError) return null; throw e; }
  }
  #fail(status: number, error: string): IssueOutput { this.#failures += 1; return fixed(status, error); }
}
