import { timingSafeEqual } from 'node:crypto';
import { publicVerif, Token, TOKEN_TYPES } from '@cloudflare/privacypass-ts';
import {
  PROTOCOL, ContractError, challengeBytes, decodeBase64Url, fromHex,
  libraryBytes, sha256, spendId, validateManifest, type Manifest,
} from '../../../contracts/lib/index.ts';

export type TokenRejection =
  | 'token-malformed'
  | 'token-type-unsupported'
  | 'token-key-unknown'
  | 'token-invalid'
  | 'token-context-mismatch'
  | 'authorization-unavailable';

export type TokenVerification =
  | { kind: 'rejected'; reason: TokenRejection }
  | { kind: 'claim-candidate'; spend_id: string; epoch: number };
export type TokenSignature = { kind: 'rejected'; reason: TokenRejection } | { kind: 'signature-valid'; receipt: object };

const reject = (reason: TokenRejection): TokenVerification => ({ kind: 'rejected', reason });

/** Public verification only. A claim-candidate is NOT authorization to forward. */
export class TokenVerifier {
  readonly #manifest: Manifest;
  readonly #keyId: Uint8Array;
  readonly #key: CryptoKey;
  readonly #origin: InstanceType<typeof publicVerif.Origin>;
  readonly #receipts = new WeakMap<object, { bytes: Uint8Array; digest: Uint8Array }>();

  private constructor(manifest: Manifest, key: CryptoKey) {
    this.#manifest = manifest;
    this.#keyId = fromHex(manifest.token_key_id, 32);
    this.#key = key;
    this.#origin = new publicVerif.Origin(publicVerif.BlindRSAMode.PSS);
  }

  /** Import once during trusted preparation; retain no reference to caller-owned config. */
  static async prepare(configuration: unknown): Promise<TokenVerifier> {
    let manifest: Manifest;
    try {
      manifest = validateManifest(structuredClone(configuration));
    } catch {
      throw new ContractError('verification-configuration-invalid');
    }
    try {
      const spki = decodeBase64Url(manifest.token_key_spki_b64url);
      const key = await crypto.subtle.importKey(
        'spki', libraryBytes(publicVerif.convertRSASSAPSSToEnc(libraryBytes(spki))),
        { name: 'RSA-PSS', hash: 'SHA-384' }, false, ['verify'],
      );
      return new TokenVerifier(manifest, key);
    } catch {
      throw new ContractError('verification-key-import-failed');
    }
  }

  /**
   * expectedEpoch must come from the trusted replay-store snapshot, not a request
   * parameter or client timestamp. The later atomic claim must recheck it.
   */
  async verify(wire: unknown, expectedEpoch: number): Promise<TokenVerification> {
    try {
      challengeBytes(this.#manifest, expectedEpoch);
    } catch {
      return reject('authorization-unavailable');
    }
    const signature = await this.verifySignature(wire);
    return signature.kind === 'rejected' ? signature : this.checkContext(signature.receipt, expectedEpoch);
  }

  /** Own the wire before awaiting crypto. The opaque receipt proves signature only, never authorization. */
  async verifySignature(wire: unknown): Promise<TokenSignature> {
    if (!(wire instanceof Uint8Array) || wire.byteLength !== PROTOCOL.token_bytes) {
      return { kind: 'rejected', reason: 'token-malformed' };
    }
    // Take ownership before the first await; caller mutation cannot change this decision.
    const bytes = libraryBytes(wire, PROTOCOL.token_bytes);
    if (new DataView(bytes.buffer).getUint16(0) !== PROTOCOL.token_type) {
      return { kind: 'rejected', reason: 'token-type-unsupported' };
    }
    const keyOffset = PROTOCOL.auth_input_bytes - this.#keyId.length;
    if (!timingSafeEqual(bytes.subarray(keyOffset, PROTOCOL.auth_input_bytes), this.#keyId)) {
      return { kind: 'rejected', reason: 'token-key-unknown' };
    }
    let token: Token;
    try {
      token = Token.deserialize(TOKEN_TYPES.BLIND_RSA, bytes);
    } catch {
      return { kind: 'rejected', reason: 'token-malformed' };
    }
    let signatureValid: boolean;
    try {
      signatureValid = await this.#origin.verify(token, this.#key);
    } catch {
      // Unexpected crypto failure is unavailable state, never a successful verification.
      return { kind: 'rejected', reason: 'authorization-unavailable' };
    }
    if (!signatureValid) return { kind: 'rejected', reason: 'token-invalid' };
    const receipt = Object.freeze({});
    this.#receipts.set(receipt, { bytes, digest: token.authInput.challengeDigest });
    return { kind: 'signature-valid', receipt };
  }

  /** Consume once, on this verifier only, after an authoritative snapshot. */
  checkContext(receipt: object, expectedEpoch: number): TokenVerification {
    const verified = this.#receipts.get(receipt);
    this.#receipts.delete(receipt);
    if (!verified) return reject('authorization-unavailable');
    let expectedDigest: Uint8Array;
    try { expectedDigest = sha256(challengeBytes(this.#manifest, expectedEpoch)); }
    catch { return reject('authorization-unavailable'); }
    if (!timingSafeEqual(verified.digest, expectedDigest)) {
      return reject('token-context-mismatch');
    }
    return {
      kind: 'claim-candidate',
      spend_id: spendId(verified.bytes.subarray(0, PROTOCOL.auth_input_bytes)),
      epoch: expectedEpoch,
    };
  }
}
