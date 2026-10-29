// Voucher cohort generation. Plaintext vouchers exist only here, in memory, until each client receives its own
// inventory; the issuer receives digests only. Every voucher comes from the OS CSPRNG. Nothing is logged or persisted.
import { randomBytes } from 'node:crypto';
import { PROTOCOL, encodeBase64Url, voucherDigest } from '../../../../contracts/lib/index.ts';
import { CLIENT_IDS, type ClientId } from './ports.ts';

export type Cohort = {
  /** Digests for the issuer, in provisioning order. */
  issuerDigests: string[];
  /** Each client's own plaintext inventory (43-char base64url). No client sees another's. */
  clientItems: Record<ClientId, string[]>;
};

export function generateCohort(perClient: number, clients: readonly ClientId[] = CLIENT_IDS): Cohort {
  if (!Number.isSafeInteger(perClient) || perClient < 1 || perClient * clients.length > PROTOCOL.client_profiles.benchmark.inventory_max) throw new Error('cohort-size');
  const clientItems = {} as Record<ClientId, string[]>;
  const issuerDigests: string[] = [];
  for (const id of clients) {
    clientItems[id] = Array.from({ length: perClient }, () => {
      const v = randomBytes(32);
      issuerDigests.push(voucherDigest(v));
      return encodeBase64Url(v, false);
    });
  }
  return { issuerDigests, clientItems };
}

/** Splits into provisioning frames of at most 128 items (the frozen per-message bound). */
export function* batches<T>(items: readonly T[], size: number = PROTOCOL.provision_batch_max): Generator<T[]> {
  for (let i = 0; i < items.length; i += size) yield items.slice(i, i + size) as T[];
}
