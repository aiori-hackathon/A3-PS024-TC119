// RFC 9578 issuer directory: public configuration only. The key uses padded base64url of the RSA-PSS SPKI.
import { PROTOCOL, encodeBase64Url } from '../../../../contracts/lib/index.ts';

export const DIRECTORY_PATH = '/.well-known/private-token-issuer-directory';
export const DIRECTORY_TYPE = 'application/private-token-issuer-directory';

export function directoryBody(publicKeySpki: Uint8Array): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    'issuer-request-uri': PROTOCOL.issuer_request_uri,
    'token-keys': [{ 'token-type': PROTOCOL.token_type, 'token-key': encodeBase64Url(publicKeySpki, true) }],
  }));
}
