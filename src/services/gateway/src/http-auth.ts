import {
  PROTOCOL, ContractError, challengeBytes, decodeBase64Url, encodeBase64Url,
  parseSnapshotReply, validateManifest, type Manifest,
} from '../../../contracts/lib/index.ts';

export type AuthorizationInput =
  | { kind: 'missing' }
  | { kind: 'token'; wire: Uint8Array<ArrayBuffer> }
  | { kind: 'rejected'; reason: 'request-malformed' | 'token-malformed' };

const tchar = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]$/;
const fieldName = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const fieldValue = /^[\t\x20-\x7e\x80-\xff]*$/;
// RFC 9110 recipients tolerate a reasonable number of empty list members.
const MAX_EMPTY_MEMBERS = 8;

function privateToken(value: string): AuthorizationInput {
  let at = 0;
  const ows = () => { while (value[at] === ' ' || value[at] === '\t') at++; };
  const token = () => {
    const start = at;
    while (at < value.length && tchar.test(value[at]!)) at++;
    if (start === at) throw new Error();
    return value.slice(start, at);
  };
  const parameterValue = () => {
    if (value[at] !== '"') return token();
    at++;
    let decoded = '';
    while (at < value.length) {
      let ch = value[at++]!;
      if (ch === '"') return decoded;
      if (ch === '\\') {
        if (at === value.length) throw new Error();
        ch = value[at++]!;
      }
      decoded += ch;
    }
    throw new Error();
  };
  try {
    ows();
    if (token().toLowerCase() !== 'privatetoken') return { kind: 'missing' };
    if (value[at] !== ' ') throw new Error();
    ows();
    const names = new Set<string>();
    let encoded: string | undefined;
    let emptyMembers = 0;
    const empty = () => { if (++emptyMembers > MAX_EMPTY_MEMBERS) throw new Error(); };
    while (at < value.length) {
      if (value[at] === ',') { empty(); at++; ows(); if (at === value.length) empty(); continue; }
      const name = token().toLowerCase();
      if (names.has(name)) throw new Error();
      names.add(name);
      ows();
      if (value[at++] !== '=') throw new Error();
      ows();
      const data = parameterValue();
      if (name === 'token') encoded = data;
      ows();
      if (at === value.length) break;
      if (value[at++] !== ',') throw new Error();
      ows();
      if (at === value.length) empty();
    }
    if (encoded === undefined) throw new Error();
    // Padding and pad bits are canonicalized by the shared decoder. Type 2 is
    // exactly 354 bytes; unsupported types of that size are classified later.
    const wire = decodeBase64Url(encoded, PROTOCOL.token_bytes);
    return { kind: 'token', wire: Uint8Array.from(wire) };
  } catch {
    return { kind: 'rejected', reason: 'token-malformed' };
  }
}

/** Pass Node's flat request.rawHeaders, NOT its merged/normalized headers map. */
export function parseAuthorization(rawHeaders: unknown): AuthorizationInput {
  const malformed = (): AuthorizationInput => ({ kind: 'rejected', reason: 'request-malformed' });
  if (!Array.isArray(rawHeaders) || rawHeaders.length % 2 !== 0
    || rawHeaders.length > PROTOCOL.gateway_common.headers_max_count * 2) return malformed();
  let bytes = 2; // End-of-headers CRLF; transport also enforces its framing limit.
  let authorization: string | undefined;
  for (let i = 0; i < rawHeaders.length; i += 2) {
    const name: unknown = rawHeaders[i], value: unknown = rawHeaders[i + 1];
    if (typeof name !== 'string' || typeof value !== 'string') return malformed();
    bytes += name.length + value.length + 4; // Latin-1 octets, colon-space and CRLF.
    if (bytes > PROTOCOL.gateway_common.headers_max_bytes) return malformed();
    if (!fieldName.test(name) || !fieldValue.test(value)) return malformed();
    if (name.toLowerCase() === 'authorization') {
      if (authorization !== undefined) return { kind: 'rejected', reason: 'token-malformed' };
      authorization = value;
    }
  }
  return authorization === undefined ? { kind: 'missing' } : privateToken(authorization);
}

export type GatewayError = keyof typeof PROTOCOL.gateway_results;
export type HttpRejection = Readonly<{
  status: number;
  headers: Readonly<Record<string, string>>;
  body: string;
}>;

/** Fixed local responses only; no socket I/O, authorization or lifecycle state. */
export class GatewayResponses {
  readonly #manifest: Manifest;
  private constructor(manifest: Manifest) { this.#manifest = manifest; }

  static prepare(configuration: unknown): GatewayResponses {
    try {
      return new GatewayResponses(validateManifest(structuredClone(configuration)));
    } catch {
      throw new ContractError('response-configuration-invalid');
    }
  }

  /** For 401, caller supplies a newly obtained snapshot and checks its live lease. */
  rejection(reason: GatewayError, snapshotReply?: unknown): HttpRejection {
    if (!Object.hasOwn(PROTOCOL.gateway_results, reason)) reason = 'authorization-unavailable';
    let status: number = PROTOCOL.gateway_results[reason];
    const headers: Record<string, string> = {
      'cache-control': 'no-store', 'content-type': 'application/json; charset=utf-8',
    };
    if (status === 401) {
      try {
        const snapshot = parseSnapshotReply(snapshotReply, this.#manifest);
        if (snapshot.tag !== 'SNAPSHOT' || snapshot.epoch === undefined) throw new Error();
        headers['www-authenticate'] = `PrivateToken challenge="${encodeBase64Url(challengeBytes(this.#manifest, snapshot.epoch))}", token-key="${this.#manifest.token_key_spki_b64url}"`;
      } catch {
        status = PROTOCOL.gateway_results['authorization-unavailable'];
        reason = 'authorization-unavailable';
      }
    }
    if (status === 405) headers['allow'] = 'GET';
    const body = JSON.stringify({ error: reason });
    headers['content-length'] = String(Buffer.byteLength(body, 'utf8'));
    return Object.freeze({ status, headers: Object.freeze(headers), body });
  }
}
