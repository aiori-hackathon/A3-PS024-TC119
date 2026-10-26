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

const reject = (reason: TokenRejection): TokenVerification => ({ kind: 'rejected', reason });

/** Public verification only. A claim-candidate is NOT authorization to forward. */
export class TokenVerifier {
  readonly #manifest: Manifest;
  readonly #keyId: Uint8Array;
  readonly #key: CryptoKey;
  readonly #origin: InstanceType<typeof publicVerif.Origin>;

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
    let expectedDigest: Uint8Array;
    try {
      expectedDigest = sha256(challengeBytes(this.#manifest, expectedEpoch));
    } catch {
      return reject('authorization-unavailable');
    }
    if (!(wire instanceof Uint8Array) || wire.byteLength !== PROTOCOL.token_bytes) {
      return reject('token-malformed');
    }
    // Take ownership before the first await; caller mutation cannot change this decision.
    const bytes = libraryBytes(wire, PROTOCOL.token_bytes);
    if (new DataView(bytes.buffer).getUint16(0) !== PROTOCOL.token_type) {
      return reject('token-type-unsupported');
    }
    const keyOffset = PROTOCOL.auth_input_bytes - this.#keyId.length;
    if (!timingSafeEqual(bytes.subarray(keyOffset, PROTOCOL.auth_input_bytes), this.#keyId)) {
      return reject('token-key-unknown');
    }
    let token: Token;
    try {
      token = Token.deserialize(TOKEN_TYPES.BLIND_RSA, bytes);
    } catch {
      return reject('token-malformed');
    }
    let signatureValid: boolean;
    try {
      signatureValid = await this.#origin.verify(token, this.#key);
    } catch {
      // Unexpected crypto failure is unavailable state, never a successful verification.
      return reject('authorization-unavailable');
    }
    if (!signatureValid) return reject('token-invalid');
    if (!timingSafeEqual(token.authInput.challengeDigest, expectedDigest)) {
      return reject('token-context-mismatch');
    }
    return {
      kind: 'claim-candidate',
      spend_id: spendId(bytes.subarray(0, PROTOCOL.auth_input_bytes)),
      epoch: expectedEpoch,
    };
  }
}
