import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { Token, TokenChallenge, TOKEN_TYPES } from '@cloudflare/privacypass-ts';
import {
  canonicalJson, ContractError, decodeBase64Url, encodeBase64Url, hex, libraryBytes, PROTOCOL, sha256, type Manifest,
} from '../../../../contracts/lib/index.ts';
import {
  REGIONAL, holderProofInput, regionalContext, regionalPolicyDigest, requireRegionalWindow,
  validateRegionalPolicy, type HolderNonce, type RegionalPolicy,
} from '../../../../contracts/lib/regional.ts';
import {
  decodeCanonicalRegionalJson, regionalType2Challenge, validateRegionalPublicRequest,
  validateRegionalPublicResponse,
} from '../../../../contracts/lib/regional-wire.ts';
import { LabIssuance, verifyTokenSignature } from '../protocol.ts';
import { LabClient, LabClientError, type ClientConfig, type Reply } from './client.ts';
import type { ClientVouchers } from './vouchers.ts';

export interface ArcClientHelper {
  begin(policy: RegionalPolicy, issuerParams: string): Promise<string>;
  finalize(response: string): Promise<void>;
  present(slot?: number): Promise<string>;
  close(): void | Promise<void>;
}
export type RegionalClientConfig = Omit<ClientConfig, 'vouchers'> & {
  policy: RegionalPolicy;
  vouchers: ClientVouchers;
  arcHelper?: ArcClientHelper;
};
export type RegionalAccessResult = {
  status: number; label: string | null; resource_b64url?: string; estimated_remaining: number; delivery: 'confirmed' | 'uncertain';
};
export type RegionalClientMeasurements = {
  issuance_interactions: number; issuance_request_bytes: number; issuance_response_bytes: number;
  preparation_interactions: number;
  preparation_ms: number; issuance_ms: number; redemption_ms: number;
};
type HolderKey = { privateKey: KeyObject; spki: string };
type Entry = { token: Uint8Array; holder?: HolderKey };

function holderKey(): HolderKey {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { privateKey: pair.privateKey, spki: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url') };
}

/** Memory-only admitted wallet. Every token has its own key in the holder profile. */
export class RegionalClient {
  readonly #policy: RegionalPolicy;
  readonly #manifest: Manifest;
  readonly #transport: LabClient;
  readonly #vouchers: ClientVouchers;
  readonly #helper: ArcClientHelper | undefined;
  readonly #now: () => number;
  readonly #entries: Entry[] = [];
  #last: Entry | undefined;
  #nextSlot = 0;
  #lastSlot: number | undefined;
  #acquired = false;
  #attempted = false;
  #closed = false;
  #helperDrained: Promise<void> = Promise.resolve();
  readonly #measurements: RegionalClientMeasurements = {
    issuance_interactions: 0, issuance_request_bytes: 0, issuance_response_bytes: 0,
    preparation_interactions: 0,
    preparation_ms: 0, issuance_ms: 0, redemption_ms: 0,
  };

  constructor(config: RegionalClientConfig) {
    this.#policy = validateRegionalPolicy(config.policy, config.manifest);
    this.#manifest = config.manifest;
    this.#transport = new LabClient(config);
    this.#vouchers = config.vouchers;
    this.#helper = config.arcHelper;
    this.#now = config.now ?? Date.now;
    if ((this.#policy.profile === 'arc') !== !!this.#helper) throw new Error('regional-client-configuration');
  }
  get estimatedRemaining(): number {
    if (this.#closed || !this.#acquired) return 0;
    return this.#policy.profile === 'arc' ? Math.max(0, REGIONAL.quota - this.#nextSlot) : this.#entries.length;
  }
  get issuedCredentials(): number {
    return this.#acquired ? this.#policy.profile === 'arc' ? 1 : REGIONAL.quota : 0;
  }
  get measurements(): RegionalClientMeasurements {
    return { ...this.#measurements, preparation_ms: Math.ceil(this.#measurements.preparation_ms),
      issuance_ms: Math.ceil(this.#measurements.issuance_ms), redemption_ms: Math.ceil(this.#measurements.redemption_ms) };
  }
  #current(): void {
    if (this.#closed) throw new ContractError('regional-client-closed');
    requireRegionalWindow(this.#policy, this.#now());
  }
  #base(): { contract_version: string; policy_digest: string } {
    return { contract_version: REGIONAL.contract_version, policy_digest: regionalPolicyDigest(this.#policy) };
  }

  async acquire(): Promise<void> {
    this.#current();
    if (this.#attempted) throw new ContractError('regional-enrollment-already-attempted');
    this.#attempted = true;
    if (this.#policy.profile === 'ip') return;
    const voucher = this.#vouchers.take();
    if (!voucher) throw new ContractError('regional-no-entitlement');
    const started = performance.now();
    try {
      const issuances: { issuance: LabIssuance; challenge: TokenChallenge; holder?: HolderKey }[] = [];
      let requests: string[];
      if (this.#policy.profile === 'arc') {
        this.#measurements.preparation_interactions++;
        const directory = await this.#transport.regionalPublic('arc_directory');
        const body = this.#response('arc-directory', directory);
        requests = [await this.#helper!.begin(this.#policy, body['issuer_params_b64url'] as string)];
      } else {
        const bearerChallenge = this.#policy.profile === 'type2-bearer' ? await this.#bearerChallenge() : undefined;
        for (let index = 0; index < REGIONAL.quota; index++) {
          const holder = this.#policy.profile === 'type2-holder' ? holderKey() : undefined;
          const challenge = holder ? await this.#holderChallenge(holder.spki) : bearerChallenge!;
          const issuance = await LabIssuance.begin(challenge, decodeBase64Url(this.#manifest.token_key_spki_b64url));
          issuances.push({ issuance, challenge, ...(holder ? { holder } : {}) });
        }
        requests = issuances.map(({ issuance }) => encodeBase64Url(issuance.requestWire, false));
      }
      this.#measurements.preparation_ms += performance.now() - started;
      const body = { ...this.#base(), profile: this.#policy.profile,
        enrollment_voucher_b64url: encodeBase64Url(voucher, false), blinded_requests_b64url: requests };
      validateRegionalPublicRequest('enroll', body, this.#policy);
      const issuanceStart = performance.now();
      this.#measurements.issuance_interactions++;
      this.#measurements.issuance_request_bytes += Buffer.byteLength(canonicalJson(body), 'utf8');
      const reply = await this.#transport.regionalPublic('enroll', body);
      this.#measurements.issuance_ms += performance.now() - issuanceStart;
      const enrollment = this.#response('enroll', reply);
      const responses = enrollment['responses_b64url'] as string[];
      this.#measurements.issuance_response_bytes += reply.body.length;
      this.#current();
      if (this.#helper) await this.#helper.finalize(responses[0]!);
      else {
        const entries: Entry[] = [];
        for (const [index, item] of issuances.entries()) {
          const token = await item.issuance.finalize(decodeBase64Url(responses[index]!, PROTOCOL.response_bytes, false));
          const parsed = Token.deserialize(TOKEN_TYPES.BLIND_RSA, libraryBytes(token));
          if (hex(parsed.authInput.challengeDigest) !== hex(sha256(item.challenge.serialize()))
            || hex(parsed.authInput.tokenKeyId) !== this.#policy.type2_key_id
            || !await verifyTokenSignature(decodeBase64Url(this.#manifest.token_key_spki_b64url), token)) {
            throw new ContractError('regional-issuance-invalid');
          }
          entries.push({ token, ...(item.holder ? { holder: item.holder } : {}) });
        }
        this.#current();
        this.#entries.push(...entries);
      }
      this.#current();
      this.#acquired = true;
    } finally { voucher.fill(0); }
  }

  async #bearerChallenge(): Promise<TokenChallenge> {
    this.#measurements.preparation_interactions++;
    const reply = await this.#transport.regionalResource();
    const values: string[] = [];
    for (let index = 0; index < reply.rawHeaders.length; index += 2) {
      if (reply.rawHeaders[index]!.toLowerCase() === 'www-authenticate') values.push(reply.rawHeaders[index + 1]!);
    }
    const match = values.length === 1
      ? /^PrivateToken challenge="([A-Za-z0-9_-]+={0,2})", token-key="([A-Za-z0-9_-]+={0,2})"$/.exec(values[0]!) : null;
    if (reply.status !== 401 || !match) throw new ContractError('regional-challenge-invalid');
    const expected = regionalType2Challenge(regionalContext(this.#policy));
    if (!Buffer.from(expected).equals(Buffer.from(decodeBase64Url(match[1]!, undefined, match[1]!.endsWith('='))))
      || !Buffer.from(decodeBase64Url(this.#manifest.token_key_spki_b64url)).equals(Buffer.from(decodeBase64Url(match[2]!)))) {
      throw new ContractError('regional-challenge-invalid');
    }
    return TokenChallenge.deserialize(libraryBytes(expected));
  }

  async #holderChallenge(spki: string): Promise<TokenChallenge> {
    this.#measurements.preparation_interactions++;
    const request = { ...this.#base(), public_key_spki_b64url: spki };
    validateRegionalPublicRequest('holder-challenge', request, this.#policy);
    const reply = this.#response('holder-challenge', await this.#transport.regionalPublic('holder_challenge', request));
    if (!Buffer.from(decodeBase64Url(reply['token_key_spki_b64url'] as string, undefined, false))
      .equals(Buffer.from(decodeBase64Url(this.#manifest.token_key_spki_b64url)))) throw new ContractError('regional-challenge-key');
    return TokenChallenge.deserialize(libraryBytes(Buffer.from(reply['challenge_b64url'] as string, 'base64url')));
  }

  #response(route: 'enroll' | 'holder-challenge' | 'holder-nonce' | 'arc-directory', reply: Reply): Record<string, unknown> {
    if (reply.status !== 200) throw new ContractError(`regional-${route}-refused`);
    if (reply.headers['content-type'] !== 'application/json') throw new ContractError('regional-response-invalid');
    const body = decodeCanonicalRegionalJson(reply.body);
    validateRegionalPublicResponse(route, body, this.#policy);
    return body as Record<string, unknown>;
  }

  async #holderRequest(entry: Entry, holder = entry.holder!): Promise<Record<string, unknown>> {
    const request = { ...this.#base(), token_hash: hex(sha256(entry.token)), public_key_spki_b64url: holder.spki };
    validateRegionalPublicRequest('holder-nonce', request, this.#policy);
    const nonce = this.#response('holder-nonce', await this.#transport.regionalPublic('holder_nonce', request)) as {
      body: HolderNonce; mac: string;
    };
    const input = holderProofInput(this.#policy, entry.token, holder.spki, nonce, this.#now());
    const proof = { ...this.#base(), public_key_spki_b64url: holder.spki, nonce,
      signature_b64url: sign('sha256', input, { key: holder.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url') };
    const body = { ...this.#base(), token_b64url: encodeBase64Url(entry.token, false), proof };
    validateRegionalPublicRequest('holder-redeem', body, this.#policy);
    return body;
  }

  async #prepare(copy = false): Promise<() => Promise<Reply>> {
    this.#current();
    if (this.#policy.profile === 'ip') return () => this.#transport.regionalResource();
    if (!this.#acquired) throw new ContractError('regional-no-token');
    if (this.#helper) {
      const slot = copy ? this.#lastSlot ?? 0 : this.#nextSlot++;
      if (slot >= REGIONAL.quota) throw new ContractError('regional-no-token');
      this.#lastSlot = slot;
      const presentation = await this.#helper.present(slot);
      const body = { ...this.#base(), presentation_b64url: presentation };
      validateRegionalPublicRequest('arc-redeem', body, this.#policy);
      return () => this.#transport.regionalPublic('arc_redeem', body);
    }
    const entry = copy ? this.#last ?? this.#entries[0] : this.#entries.shift();
    if (!entry) throw new ContractError('regional-no-token');
    if (this.#last && this.#last !== entry && !this.#entries.includes(this.#last)) this.#last.token.fill(0);
    this.#last = entry;
    if (!entry.holder) return () => this.#transport.regionalResource(entry.token);
    const body = await this.#holderRequest(entry);
    return () => this.#transport.regionalPublic('holder_redeem', body);
  }

  async access(): Promise<RegionalAccessResult> { return this.#observe(await this.#prepare()); }
  /** Private harness only. Reoffers one bounded retained token or a randomized proof for a retained slot. */
  async copyAccess(): Promise<RegionalAccessResult> { return this.#observe(await this.#prepare(true)); }
  /** Private harness only. Token bytes with an attacker-owned key leave the owner inventory intact. */
  async attack(): Promise<RegionalAccessResult> {
    this.#current();
    const entry = this.#entries[0] ?? this.#last;
    if (this.#policy.profile === 'type2-holder' && entry) {
      const body = await this.#holderRequest(entry, holderKey());
      return this.#observe(() => this.#transport.regionalPublic('holder_redeem', body));
    }
    if (this.#helper) {
      const bytes = Buffer.from(await this.#helper.present(this.#lastSlot ?? 0), 'base64url');
      bytes[0] = bytes[0]! ^ 1;
      const body = { ...this.#base(), presentation_b64url: bytes.toString('base64url') };
      return this.#observe(() => this.#transport.regionalPublic('arc_redeem', body));
    }
    if (entry) return this.#observe(() => this.#transport.regionalResource(entry.token));
    throw new ContractError('regional-no-token');
  }
  /** One prepared valid request raced without retries. The gateway decides the sole successful claim. */
  async race(count = 20): Promise<RegionalAccessResult[]> {
    if (!Number.isSafeInteger(count) || count < 2 || count > 20) throw new ContractError('regional-race-count');
    const send = await this.#prepare();
    return Promise.all(Array.from({ length: count }, () => this.#observe(send)));
  }

  /** Laboratory abuse workload sends every request, reoffering used credentials after the admitted budget. */
  async abuse(count = 26): Promise<RegionalAccessResult[]> {
    if (!Number.isSafeInteger(count) || count < 1 || count > 26) throw new ContractError('regional-abuse-count');
    const results: RegionalAccessResult[] = [];
    for (let index = 0; index < count; index++) {
      const copy = this.#policy.profile !== 'ip' && this.estimatedRemaining === 0;
      results.push(await this.#observe(await this.#prepare(copy)));
    }
    return results;
  }

  async #observe(send: () => Promise<Reply>): Promise<RegionalAccessResult> {
    this.#current();
    const started = performance.now();
    try {
      const reply = await send();
      let label: string | null = null;
      if (reply.status !== 200) {
        try {
          const error = (JSON.parse(reply.body.toString('utf8')) as { error?: unknown }).error;
          if (typeof error === 'string' && Object.hasOwn(PROTOCOL.gateway_results, error)) label = error;
        } catch { /* Refusal bodies are never copied into evidence. */ }
      }
      return { status: reply.status, label, delivery: 'confirmed', ...(reply.status === 200 ? { resource_b64url: reply.body.toString('base64url') } : {}),
        estimated_remaining: this.estimatedRemaining };
    } catch (error) {
      if (!(error instanceof LabClientError)) throw error;
      return { status: 0, label: 'authorization-unavailable', delivery: 'uncertain', estimated_remaining: this.estimatedRemaining };
    } finally { this.#measurements.redemption_ms += performance.now() - started; }
  }

  close(): void {
    this.#closed = true;
    this.#transport.close();
    this.#helperDrained = Promise.resolve(this.#helper?.close());
    for (const entry of this.#entries.splice(0)) entry.token.fill(0);
    this.#last?.token.fill(0);
    this.#last = undefined;
  }
  drain(): Promise<void> { return this.#helperDrained; }
}
