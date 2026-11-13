// Additive regional encodings and structural contracts. These do not authorize requests.
import { createPublicKey, ECDH } from 'node:crypto';
import spec from './regional-v1.json' with {type:'json'};
import policySchema from '../schemas/regional-policy-v1.json' with {type:'json'};
import nonceSchema from '../schemas/regional-holder-nonce-v1.json' with {type:'json'};
import proofSchema from '../schemas/regional-holder-proof-v1.json' with {type:'json'};
import requestSchema from '../schemas/regional-arc-request-v1.json' with {type:'json'};
import responseSchema from '../schemas/regional-arc-response-v1.json' with {type:'json'};
import { assertSchema, ContractError, deepFreeze, type Schema } from './schema.ts';
import { canonicalJson, configurationDigest, decodeBase64Url, encodeBase64Url, hex, sha256, PROTOCOL, type Manifest } from './index.ts';

export const REGIONAL = deepFreeze(spec);
export const REGIONAL_CONTRACT_VERSION = spec.contract_version;
export type RegionalProfile = 'ip'|'type2-bearer'|'arc'|'type2-holder';
export type RegionalPolicy = {
  contract_version:string;schema_version:1;run_id:string;baseline_config_digest:string;profile:RegionalProfile;
  window_start_ms:number;window_end_ms:number;quota:5;admitted_entitlements:5;
  resource_id:'research-resource';method:'GET';url:'https://origin.lab.test/resource';
  type2_key_id:string|null;arc_key_id:string|null;arc_implementation_revision:string|null;arc_tag_encoding:string|null;
};
export type HolderNonce = {
  contract_version:string;run_id:string;policy_digest:string;token_hash:string;holder_key_hash:string;
  issued_ms:number;expires_ms:number;random_b64url:string;
};
export type HolderProof = {
  contract_version:string;policy_digest:string;public_key_spki_b64url:string;
  nonce:{body:HolderNonce;mac:string};signature_b64url:string;
};
type ArcBinding = {contract_version:string;run_id:string;policy_digest:string;request_id:string;service_incarnation:string};
export type ArcRequest = ArcBinding & (
  {operation:'issue';grant_id:string;blinded_request_b64url:string} |
  {operation:'verify';presentation_b64url:string}
);
export type ArcResponse = ArcBinding & {request_digest:string} & (
  {operation:'issue';status:'issued';credential_response_b64url:string} |
  {operation:'verify';status:'verified';spend_tag_b64url:string} |
  {operation:'issue'|'verify';status:'refused';code:string}
);

// Array framing is deliberately shared with Rust: domain followed by ordered fields.
export function regionalBytes(domain:string, ...fields:unknown[]):Uint8Array {
  return Uint8Array.from(Buffer.from(canonicalJson([domain,...fields]),'utf8'));
}
export function validateRegionalPolicy(value:unknown, baseline?:Manifest):RegionalPolicy {
  assertSchema(policySchema as Schema,value);
  const p=value as RegionalPolicy;
  if(p.window_end_ms-p.window_start_ms!==spec.window_ms)throw new ContractError('regional-window');
  if(p.window_end_ms>Number.MAX_SAFE_INTEGER-PROTOCOL.guard_ms)throw new ContractError('regional-window-overflow');
  if(baseline && (p.run_id!==baseline.run_id || p.baseline_config_digest!==configurationDigest(baseline)
    || p.window_start_ms<baseline.run_start_ms || p.window_end_ms>baseline.run_start_ms+baseline.epoch_ms
    || (p.type2_key_id!==null && p.type2_key_id!==baseline.token_key_id)))throw new ContractError('regional-baseline-binding');
  return deepFreeze(structuredClone(p));
}
export function regionalPolicyDigest(value:RegionalPolicy):string {
  const p=validateRegionalPolicy(value);
  return hex(sha256(regionalBytes(spec.domains.policy,p)));
}
export function requireRegionalWindow(p:RegionalPolicy,nowMs:number):void {
  validateRegionalPolicy(p);
  if(!Number.isSafeInteger(nowMs)||nowMs<p.window_start_ms||nowMs>=p.window_end_ms)throw new ContractError('regional-window-closed');
}
export function regionalContext(p:RegionalPolicy,kind:'context'|'arc_request_context'|'arc_presentation_context'='context'):Uint8Array {
  return sha256(regionalBytes(spec.domains[kind],regionalPolicyDigest(p)));
}
export function holderKeyHash(spkiB64url:string):string {
  const bytes=decodeBase64Url(spkiB64url,spec.holder_spki_bytes,false);
  try {
    const key=createPublicKey({key:Buffer.from(bytes),format:'der',type:'spki'});
    if(key.asymmetricKeyType!=='ec'||key.asymmetricKeyDetails?.namedCurve!=='prime256v1'
      || !Buffer.from(bytes).equals(key.export({format:'der',type:'spki'})))throw new Error();
  } catch {throw new ContractError('regional-holder-key');}
  return hex(sha256(bytes));
}
export function holderContextInput(p:RegionalPolicy,spkiB64url:string):Uint8Array {
  if(p.profile!=='type2-holder')throw new ContractError('regional-profile');
  return regionalBytes(spec.domains.holder_context,regionalPolicyDigest(p),holderKeyHash(spkiB64url));
}
export function validateHolderNonce(value:unknown,p:RegionalPolicy,nowMs:number):HolderNonce {
  assertSchema(nonceSchema as Schema,value);requireRegionalWindow(p,nowMs);
  const n=value as HolderNonce;
  if(p.profile!=='type2-holder'||n.run_id!==p.run_id||n.policy_digest!==regionalPolicyDigest(p)
    || n.issued_ms<p.window_start_ms||n.issued_ms>nowMs||n.expires_ms>p.window_end_ms
    || n.expires_ms<=n.issued_ms||n.expires_ms-n.issued_ms>spec.nonce_lifetime_ms||nowMs>=n.expires_ms)
    throw new ContractError('regional-nonce-binding');
  decodeBase64Url(n.random_b64url,32,false);
  return deepFreeze(structuredClone(n));
}
export function holderNonceMacInput(value:HolderNonce):Uint8Array {
  assertSchema(nonceSchema as Schema,value);
  decodeBase64Url(value.random_b64url,32,false);
  return regionalBytes(spec.domains.holder_nonce,value);
}
export function holderProofInput(p:RegionalPolicy,token:Uint8Array,spkiB64url:string,
  nonce:{body:HolderNonce;mac:string},nowMs:number):Uint8Array {
  if(!(token instanceof Uint8Array)||token.length!==354)throw new ContractError('regional-token-size');
  const n=validateHolderNonce(nonce.body,p,nowMs);
  const keyHash=holderKeyHash(spkiB64url),tokenHash=hex(sha256(token));
  if(!/^[0-9a-f]{64}$/.test(nonce.mac)||n.holder_key_hash!==keyHash||n.token_hash!==tokenHash)
    throw new ContractError('regional-proof-binding');
  // Caller must verify the nonce MAC, holder signature, token and bound challenge.
  return regionalBytes(spec.domains.holder_proof,regionalPolicyDigest(p),tokenHash,keyHash,
    'POST',spec.routes.holder_redeem,p.method,p.url,hex(sha256(new Uint8Array())),{body:n,mac:nonce.mac});
}
export function validateHolderProof(value:unknown,p:RegionalPolicy,token:Uint8Array,nowMs:number):HolderProof {
  assertSchema(proofSchema as Schema,value);
  const proof=value as HolderProof;
  if(proof.policy_digest!==regionalPolicyDigest(p))throw new ContractError('regional-proof-policy');
  holderProofInput(p,token,proof.public_key_spki_b64url,proof.nonce,nowMs);
  decodeBase64Url(proof.signature_b64url,spec.holder_signature_bytes,false);
  return deepFreeze(structuredClone(proof));
}
export function validateArcRequest(value:unknown,p:RegionalPolicy):ArcRequest {
  assertSchema(requestSchema as Schema,value);const r=value as ArcRequest;
  if(p.profile!=='arc'||r.run_id!==p.run_id||r.policy_digest!==regionalPolicyDigest(p))throw new ContractError('regional-arc-policy');
  boundedArcBlob(r.operation==='issue'?r.blinded_request_b64url:r.presentation_b64url);
  return deepFreeze(structuredClone(r));
}
function boundedArcBlob(value:string):void {
  // The baseline base64 helper intentionally caps at 4096 characters. ARC is separately bounded.
  if(!/^[A-Za-z0-9_-]+$/.test(value)||value.length>32768)throw new ContractError('regional-arc-blob');
  const bytes=Buffer.from(value,'base64url');
  if(!bytes.length||bytes.length>spec.arc_blob_max_bytes||bytes.toString('base64url')!==value)throw new ContractError('regional-arc-blob');
}
export function validateArcResponse(value:unknown,request:ArcRequest,p:RegionalPolicy):ArcResponse {
  const r=validateArcRequest(request,p);assertSchema(responseSchema as Schema,value);const reply=value as ArcResponse;
  for(const k of ['run_id','policy_digest','request_id','service_incarnation','operation'] as const)
    if(reply[k]!==r[k])throw new ContractError('regional-arc-response-binding');
  if(reply.request_digest!==hex(sha256(Buffer.from(canonicalJson(r),'utf8'))))throw new ContractError('regional-arc-response-binding');
  if(reply.status==='issued')boundedArcBlob(reply.credential_response_b64url);
  if(reply.status==='verified')arcTag(reply.spend_tag_b64url);
  return deepFreeze(structuredClone(reply));
}
function arcTag(value:string):Uint8Array {
  const tag=decodeBase64Url(value,spec.arc_tag_bytes,false);
  if(tag[0]!==2&&tag[0]!==3)throw new ContractError('regional-arc-tag-encoding');
  try{ECDH.convertKey(tag,'prime256v1',undefined,undefined,'compressed');}
  catch{throw new ContractError('regional-arc-tag-encoding');}
  return tag;
}
export function arcSpendId(p:RegionalPolicy,verifiedTagB64url:string):string {
  if(p.profile!=='arc')throw new ContractError('regional-profile');
  return hex(sha256(regionalBytes(spec.domains.arc_spend,regionalPolicyDigest(p),encodeBase64Url(arcTag(verifiedTagB64url),false))));
}
export function arcRpcMacInput(direction:'request'|'response',operation:'issue'|'verify',body:ArcRequest|ArcResponse):Uint8Array {
  if(!['request','response'].includes(direction)||!['issue','verify'].includes(operation)||body.operation!==operation)
    throw new ContractError('regional-rpc-direction');
  assertSchema((direction==='request'?requestSchema:responseSchema) as Schema,body);
  return regionalBytes(spec.domains.arc_rpc,direction,operation,body);
}
export function encodeRegionalFrame(body:ArcRequest|ArcResponse,mac:string):Uint8Array {
  if(!/^[0-9a-f]{64}$/.test(mac))throw new ContractError('regional-rpc-mac');
  const frame=Buffer.from(canonicalJson({body,mac})+'\n','utf8');
  if(frame.length>spec.rpc_frame_max_bytes)throw new ContractError('regional-frame-size');
  return Uint8Array.from(frame);
}
