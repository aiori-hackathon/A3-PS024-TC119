// Strict parse of the gateway's 401 challenge. The pinned library's header parser is lenient (it strips quotes
// anywhere and keeps the last duplicate), so syntax is checked here first and the library only decodes the
// already-validated RFC 9577 challenge bytes. The client trusts nothing the gateway says beyond the pinned manifest.
import { TokenChallenge } from '@cloudflare/privacypass-ts';
import {
  ContractError, PROTOCOL, decodeBase64Url, encodeBase64Url, epochAt, libraryBytes, redemptionContext, hex, type Manifest,
} from '../../../../contracts/lib/index.ts';

const SHAPE = /^PrivateToken challenge="([A-Za-z0-9_-]+={0,2})", token-key="([A-Za-z0-9_-]+={0,2})"$/;
// Canonical base64url, padded or not; anything else (stray bits, mixed padding) is rejected by the shared decoder.
const either = (v: string): Uint8Array => {
  try { return decodeBase64Url(v, undefined, true); } catch { return decodeBase64Url(v, undefined, false); }
};

export type ParsedChallenge = { challenge: TokenChallenge; epoch: number };

/** `acceptEpochs` are the epochs this client is willing to receive a challenge for (current epoch and neighbors). */
export function parseChallenge(headerValues: string[], m: Manifest, acceptEpochs: number[]): ParsedChallenge {
  if (headerValues.length !== 1) throw new ContractError('challenge-header');
  const match = SHAPE.exec(headerValues[0]!);
  if (!match) throw new ContractError('challenge-header');
  let challengeBytes: Uint8Array, tokenKey: Uint8Array;
  try { challengeBytes = either(match[1]!); tokenKey = either(match[2]!); } catch { throw new ContractError('challenge-header'); }
  // Pinned trust: the advertised key must be the manifest key, byte for byte.
  if (encodeBase64Url(tokenKey, true) !== m.token_key_spki_b64url) throw new ContractError('challenge-key');
  let challenge: TokenChallenge;
  try {
    challenge = TokenChallenge.deserialize(libraryBytes(challengeBytes));
    if (hex(challenge.serialize()) !== hex(challengeBytes)) throw new Error('non-canonical');
  } catch { throw new ContractError('challenge-malformed'); }
  if (challenge.tokenType !== PROTOCOL.token_type || challenge.issuerName !== m.issuer_name
    || challenge.originInfo?.length !== 1 || challenge.originInfo[0] !== m.origin_name || challenge.redemptionContext.length !== 32) {
    throw new ContractError('challenge-identity');
  }
  const ctx = hex(challenge.redemptionContext);
  const epoch = acceptEpochs.find((e) => e >= 0 && hex(redemptionContext(m, e)) === ctx);
  if (epoch === undefined) throw new ContractError('challenge-context');
  return { challenge, epoch };
}

/** The epochs a client with a sane clock may be offered: current, previous and next. */
export function plausibleEpochs(m: Manifest, nowMs: number): number[] {
  const cur = epochAt(m, Math.max(nowMs, m.run_start_ms)).epoch;
  return [cur - 1, cur, cur + 1].filter((e) => e >= 0);
}
