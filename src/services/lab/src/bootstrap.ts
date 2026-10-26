// G0 lab build/runtime smoke entry only. No listener, issuer service or controller exists yet.
// Real issuer/client/controller/origin roles will be separate entry points in this package.
import { CONTRACT_VERSION, PROTOCOL, configurationDigest, gatewayLimits, hex, sha256, makeManifest, encodeBase64Url } from '../../../contracts/lib/index.ts';
import { LabIssuer, LabIssuance, challengeFor, verifyTokenSignature } from './protocol.ts';

const issuer = await LabIssuer.generate(PROTOCOL.issuer_name);
const manifest = makeManifest({
  run_id: hex(crypto.getRandomValues(new Uint8Array(16))), run_start_ms: Date.now(),
  token_key_spki_b64url: encodeBase64Url(issuer.publicKeySpki),
  snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40),
});
const issuance = await LabIssuance.begin(challengeFor(manifest, 0), issuer.publicKeySpki);
const token = await issuance.finalize(await issuer.sign(issuance.requestWire));
const verified = await verifyTokenSignature(issuer.publicKeySpki, token);
if (!verified || issuance.requestWire.length !== PROTOCOL.request_bytes || token.length !== PROTOCOL.token_bytes) {
  throw new Error('Lab bootstrap cryptographic roundtrip failed');
}
console.log(JSON.stringify({
  component: 'lab-contract-bootstrap',
  contract_version: CONTRACT_VERSION,
  node_major: Number(process.versions.node.split('.')[0]),
  profiles_digest: configurationDigest({ B0: gatewayLimits('B0'), B1: gatewayLimits('B1') }),
  request_bytes: issuance.requestWire.length,
  token_bytes: token.length,
  verified,
  key_id_prefix: hex(sha256(issuer.publicKeySpki)).slice(0, 8),
}));
