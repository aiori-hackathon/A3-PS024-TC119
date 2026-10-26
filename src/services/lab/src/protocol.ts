// Lab-side Type 2 (RFC 9578) wrappers. Consumes the shared contract; defines no constants of its own.
// Every buffer crossing the pinned library boundary is copied to a standalone Uint8Array first.
import { publicVerif, Token, TokenChallenge, TOKEN_TYPES } from '@cloudflare/privacypass-ts';
import {
  PROTOCOL, ContractError, libraryBytes, tokenWire, redemptionContext, type Manifest,
} from '../../../contracts/lib/index.ts';

const { BlindRSAMode, Client, Issuer, Origin, TokenRequest, TokenResponse, getPublicKeyBytes, convertRSASSAPSSToEnc } = publicVerif;
const MODE = BlindRSAMode.PSS;

export function challengeFor(m: Manifest, epoch: number): TokenChallenge {
  return new TokenChallenge(PROTOCOL.token_type, m.issuer_name, redemptionContext(m, epoch), [m.origin_name]);
}

/** Issuer side. Holds the memory-only key pair; the private key is never exposed by this class. */
export class LabIssuer {
  readonly #issuer: InstanceType<typeof Issuer>;
  readonly publicKeySpki: Uint8Array<ArrayBuffer>;
  private constructor(issuer: InstanceType<typeof Issuer>, spki: Uint8Array<ArrayBuffer>) {
    this.#issuer = issuer;
    this.publicKeySpki = spki;
  }
  static async generate(issuerName: string): Promise<LabIssuer> {
    const keys = await Issuer.generateKey(MODE, { modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) });
    const spki = libraryBytes(await getPublicKeyBytes(keys.publicKey));
    return new LabIssuer(new Issuer(MODE, issuerName, keys.privateKey, keys.publicKey), spki);
  }
  /** One blind signature for one complete request; wrong size is rejected before any signing. */
  async sign(requestWire: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
    const request = TokenRequest.deserialize(TOKEN_TYPES.BLIND_RSA, libraryBytes(requestWire, PROTOCOL.request_bytes));
    return libraryBytes((await this.#issuer.issue(request)).serialize(), PROTOCOL.response_bytes);
  }
}

/** One library Client per outstanding issuance (it holds the blinding state for exactly one request). */
export class LabIssuance {
  readonly #client: InstanceType<typeof Client>;
  readonly requestWire: Uint8Array<ArrayBuffer>;
  #finalized = false;
  private constructor(client: InstanceType<typeof Client>, requestWire: Uint8Array<ArrayBuffer>) {
    this.#client = client;
    this.requestWire = requestWire;
  }
  static async begin(challenge: TokenChallenge, issuerSpki: Uint8Array): Promise<LabIssuance> {
    const client = new Client(MODE);
    const request = await client.createTokenRequest(challenge, libraryBytes(issuerSpki));
    return new LabIssuance(client, libraryBytes(request.serialize(), PROTOCOL.request_bytes));
  }
  async finalize(responseWire: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
    if (this.#finalized) throw new ContractError('issuance-finalized');
    this.#finalized = true;
    const response = TokenResponse.deserialize(libraryBytes(responseWire, PROTOCOL.response_bytes));
    return libraryBytes(tokenWire((await this.#client.finalize(response)).serialize()), PROTOCOL.token_bytes);
  }
}

/** Public-key-only verification, exactly what a verifier without issuer secrets can do. */
export async function verifyTokenSignature(issuerSpki: Uint8Array, wire: Uint8Array): Promise<boolean> {
  const key = await crypto.subtle.importKey('spki', libraryBytes(convertRSASSAPSSToEnc(libraryBytes(issuerSpki))),
    { name: 'RSA-PSS', hash: 'SHA-384' }, false, ['verify']);
  return new Origin(MODE).verify(Token.deserialize(TOKEN_TYPES.BLIND_RSA, tokenWire(wire)), key);
}
