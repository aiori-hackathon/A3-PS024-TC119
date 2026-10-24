import { createHash, createPublicKey } from 'node:crypto';
import protocol from '../protocol-v1.json' with { type: 'json' };
import manifestSchema from '../schemas/run-manifest-v1.json' with { type: 'json' };
import requestSchema from '../schemas/control-request-v1.json' with { type: 'json' };
import responseSchema from '../schemas/control-response-v1.json' with { type: 'json' };
import reportSchema from '../schemas/report-v1.schema.json' with { type: 'json' };
import { assertSchema, ContractError, deepFreeze, type Schema } from './schema.ts';
export { assertSchema, conforms, ContractError } from './schema.ts';
export const CONTRACT_VERSION = protocol.contract_version;
export const PROTOCOL = deepFreeze(protocol);
export type GatewayProfile = 'B0' | 'B1';
export type ClientProfile = 'demo' | 'security' | 'benchmark';
export function gatewayLimits(profile: GatewayProfile) {
  if (profile !== 'B0' && profile !== 'B1') throw new ContractError('unknown-profile');
  return { ...protocol.gateway_common, ...protocol.gateway_profiles[profile] };
}
export type Manifest = {
  schema_version:1; contract_version:string; policy_version:1; run_id:string;run_start_ms:number;
  epoch_ms:number;guard_ms:number;token_type:2;token_key_id:string;token_key_spki_b64url:string;
  issuer_name:string;origin_name:string;resource_scope:string;issuer_request_uri:string;
  snapshot_script_sha1:string;claim_script_sha1:string;gateway_profile:GatewayProfile;client_profile:ClientProfile;
  inventory_total:number; endpoints:typeof protocol.endpoints;
  limits:{gateway:ReturnType<typeof gatewayLimits>;issuer:typeof protocol.issuer_limits;
    client:typeof protocol.client_profiles.demo;control_message_max_bytes:number;provision_batch_max:number};
};
export function canonicalJson(value: unknown): string {
  const seen = new Set<object>();
  const visit = (v: unknown, depth:number):string => {
    if(depth>32) throw new ContractError('canonical-depth');
    if(v === null || typeof v === 'boolean') return JSON.stringify(v);
    if(typeof v === 'number' && Number.isSafeInteger(v) && v>=0 && !Object.is(v,-0)) return String(v);
    if(typeof v === 'string' && /^[\x20-\x7e]*$/.test(v)) return JSON.stringify(v);
    if(v && typeof v === 'object') {
      if(seen.has(v)) throw new ContractError('canonical-cycle');
      if(!Array.isArray(v) && ![Object.prototype,null].includes(Object.getPrototypeOf(v))) throw new ContractError('canonical-object');
      seen.add(v);
      let result:string;
      if(Array.isArray(v)) {
        if(Object.keys(v).length!==v.length) throw new ContractError('canonical-array');
        result='['+v.map(x=>visit(x,depth+1)).join(',')+']';
      } else {
        const record=v as Record<string,unknown>;
        result='{'+Object.keys(record).sort().map(k=>{
          if(!/^[\x20-\x7e]+$/.test(k)) throw new ContractError('canonical-key');
          return JSON.stringify(k)+':'+visit(record[k],depth+1);
        }).join(',')+'}';
      }
      seen.delete(v); return result;
    }
    throw new ContractError('canonical-value');
  };
  return visit(value,0);
}
export function sha256(data:Uint8Array|string):Uint8Array {return Uint8Array.from(createHash('sha256').update(data).digest());}
export function hex(data:Uint8Array):string { return Buffer.from(data).toString('hex'); }
export function configurationDigest(value:unknown):string {return hex(sha256(canonicalJson(value)));}
export function fromHex(value:string, bytes:number):Uint8Array {
  if(!new RegExp(`^[0-9a-f]{${bytes*2}}$`).test(value)) throw new ContractError('hex-invalid');
  return Uint8Array.from(Buffer.from(value,'hex'));
}
export function libraryBytes(value:Uint8Array, length?:number):Uint8Array<ArrayBuffer> {
  if(!(value instanceof Uint8Array) || (length !== undefined && value.byteLength !== length)) throw new ContractError('wire-length');
  // Buffer.from/subarray may share pooled backing memory. The pinned parser ignores offsets.
  return Uint8Array.from(value);
}
export function encodeBase64Url(value:Uint8Array,padded=true):string {
  const s=Buffer.from(value).toString('base64').replaceAll('+','-').replaceAll('/','_');
  return padded?s:s.replace(/=+$/,'');
}
export function decodeBase64Url(value:string, length?:number, padded=true):Uint8Array {
  if(typeof value!=='string' || value.length>4096 || !/^[A-Za-z0-9_-]+={0,2}$/.test(value)) throw new ContractError('base64url-invalid');
  const bytes=Uint8Array.from(Buffer.from(value,'base64url'));
  if(encodeBase64Url(bytes,padded)!==value || (length!==undefined && bytes.length!==length)) throw new ContractError('base64url-invalid');
  return bytes;
}
export function validateManifest(value:unknown):Manifest {
  assertSchema(manifestSchema as Schema,value);
  const m=value as Manifest;
  const key=decodeBase64Url(m.token_key_spki_b64url,undefined,true);
  if(hex(sha256(key))!==m.token_key_id) throw new ContractError('key-id-mismatch');
  try {
    if(key[0]!==0x30||key.length<4)throw new Error();
    const first=key[1]!; const n=first<128?0:first&127;
    if(n>3||first===128||(n>0&&key[2]===0))throw new Error();
    let payload=n===0?first:0;
    for(let i=0;i<n;i++)payload=payload*256+key[2+i]!;
    if((n>0&&payload<128)||payload+2+n!==key.length)throw new Error();
    const parsed=createPublicKey({key:Buffer.from(key),format:'der',type:'spki'});
    const d=parsed.asymmetricKeyDetails;
    if(parsed.asymmetricKeyType!=='rsa-pss'||d?.modulusLength!==2048||d.publicExponent!==65537n||d.hashAlgorithm!=='sha384'||d.mgf1HashAlgorithm!=='sha384'||d.saltLength!==48)throw new Error();
    // OpenSSL normalizes AlgorithmIdentifier parameters on export; byte equality
    // with its re-encoding would incorrectly reject the RFC/library SPKI.
  } catch { throw new ContractError('public-key-invalid'); }
  return m;
}
export function makeManifest(fields:Pick<Manifest,'run_id'|'run_start_ms'|'token_key_spki_b64url'|'snapshot_script_sha1'|'claim_script_sha1'> &
  {gateway_profile?:GatewayProfile;client_profile?:ClientProfile;inventory_total?:number}):Manifest {
  const gp=fields.gateway_profile??'B1'; const cp=fields.client_profile??'demo';
  const m={schema_version:1,contract_version:CONTRACT_VERSION,policy_version:1,run_id:fields.run_id,run_start_ms:fields.run_start_ms,
    epoch_ms:protocol.epoch_ms,guard_ms:protocol.guard_ms,token_type:2,token_key_id:hex(sha256(decodeBase64Url(fields.token_key_spki_b64url))),
    token_key_spki_b64url:fields.token_key_spki_b64url,issuer_name:protocol.issuer_name,origin_name:protocol.origin_name,
    resource_scope:protocol.resource_scope,issuer_request_uri:protocol.issuer_request_uri,snapshot_script_sha1:fields.snapshot_script_sha1,
    claim_script_sha1:fields.claim_script_sha1,gateway_profile:gp,client_profile:cp,inventory_total:fields.inventory_total??protocol.client_profiles[cp].inventory_max,
    endpoints:{...protocol.endpoints},limits:{gateway:gatewayLimits(gp),issuer:{...protocol.issuer_limits},client:{...protocol.client_profiles[cp]},
      control_message_max_bytes:protocol.control_message_max_bytes,provision_batch_max:protocol.provision_batch_max}};
  return validateManifest(m);
}
function uint(value:number,bytes:2|8):Uint8Array {
  if(!Number.isSafeInteger(value)||value<0) throw new ContractError('integer-invalid');
  const b=new Uint8Array(bytes); const view=new DataView(b.buffer);
  if(bytes===2) {if(value>65535)throw new ContractError('integer-overflow');view.setUint16(0,value);}
  else view.setBigUint64(0,BigInt(value));
  return b;
}
function ascii(value:string):Uint8Array {if(!/^[\x20-\x7e]*$/.test(value))throw new ContractError('ascii-invalid');return new TextEncoder().encode(value);}
function concat(...parts:Uint8Array[]):Uint8Array {
  const out=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let at=0;
  for(const p of parts){out.set(p,at);at+=p.length;} return out;
}
function lp(value:string):Uint8Array {const b=ascii(value);return concat(uint(b.length,2),b);}
export function epochBounds(m:Manifest,epoch:number) {
  if(!Number.isSafeInteger(epoch)||epoch<0)throw new ContractError('epoch-invalid');
  const start=BigInt(m.run_start_ms)+BigInt(epoch)*BigInt(m.epoch_ms);
  const end=start+BigInt(m.epoch_ms);
  if(end+BigInt(m.guard_ms)>BigInt(Number.MAX_SAFE_INTEGER))throw new ContractError('time-overflow');
  return {epoch,start_ms:Number(start),end_ms:Number(end)};
}
export function epochAt(m:Manifest,now:number) {
  if(!Number.isSafeInteger(now)||now<m.run_start_ms) throw new ContractError('clock-unsafe');
  const epoch=Number((BigInt(now)-BigInt(m.run_start_ms))/BigInt(m.epoch_ms));
  return epochBounds(m,epoch);
}
export function contextInput(m:Manifest,epoch:number):Uint8Array {
  const b=epochBounds(m,epoch);
  return concat(ascii(protocol.domains.context),uint(2,2),fromHex(m.run_id,16),fromHex(m.token_key_id,32),
    uint(epoch,8),uint(b.start_ms,8),uint(b.end_ms,8),lp(m.issuer_name),lp(m.origin_name),lp(m.resource_scope));
}
export function redemptionContext(m:Manifest,epoch:number):Uint8Array {return sha256(contextInput(m,epoch));}
export function challengeBytes(m:Manifest,epoch:number):Uint8Array {
  // RFC 9577 encoding, checked independently against library serialization in tests.
  const context=redemptionContext(m,epoch);
  return concat(uint(2,2),lp(m.issuer_name),Uint8Array.of(32),context,lp(m.origin_name));
}
export function authenticatorInput(nonce:Uint8Array,challengeDigest:Uint8Array,keyId:Uint8Array):Uint8Array {
  return concat(uint(2,2),libraryBytes(nonce,32),libraryBytes(challengeDigest,32),libraryBytes(keyId,32));
}
export function spendId(authInput:Uint8Array):string {
  const b=libraryBytes(authInput,98);
  if(new DataView(b.buffer).getUint16(0)!==2)throw new ContractError('token-type-unsupported');
  return hex(sha256(concat(ascii(protocol.domains.spend),b)));
}
export function voucherDigest(voucher:Uint8Array):string {return hex(sha256(concat(ascii(protocol.domains.voucher),libraryBytes(voucher,32))));}
export function tokenWire(value:Uint8Array):Uint8Array {
  const b=libraryBytes(value,354);
  if(new DataView(b.buffer).getUint16(0)!==2)throw new ContractError('token-type-unsupported');
  return b;
}
export function validateControlRequest(value:unknown):Record<string,unknown> {
  assertSchema(requestSchema as Schema,value);
  if(Buffer.byteLength(JSON.stringify(value),'utf8')>protocol.control_message_max_bytes)throw new ContractError('control-too-large');
  const r=value as Record<string,unknown>;
  const payload=r['payload'] as Record<string,unknown>;
  if(r['command']==='PREPARE_RUN') {
    const m=validateManifest(payload['manifest']);
    if(r['run_id']!==m.run_id||payload['proposed_config_digest']!==configurationDigest(m))throw new ContractError('prepare-mismatch');
  }
  if(r['command']==='PROVISION_CLIENT') {
    for(const v of payload['items'] as string[]) decodeBase64Url(v,32,false);
  }
  return r;
}
export function validateControlResponse(value:unknown):void {assertSchema(responseSchema as Schema,value);}
export function validateReport(value:unknown):void {
  assertSchema(reportSchema as Schema,value);
  const r=value as {overall_status:string;suite_kind:'demo'|'security'|'benchmark';runs:{scenario_results:{scenario_id:string;status:string;origin_counts_available:boolean}[];measurements:{count:number;histogram_counts:number[];p50_ms:number|null;p95_ms:number|null;p99_ms:number|null}[]}[]};
  if(r.overall_status==='PASS' && (r.runs.length===0||r.runs.some(x=>x.scenario_results.length===0||x.scenario_results.some(s=>s.status!=='PASS'||!s.origin_counts_available))))throw new ContractError('missing-evidence');
  if(r.overall_status==='PASS') {
    const observed=new Set(r.runs.flatMap(run=>run.scenario_results.map(s=>s.scenario_id)));
    if(protocol.suite_required_scenarios[r.suite_kind].some(id=>!observed.has(id)))throw new ContractError('missing-evidence');
  }
  for(const run of r.runs)for(const m of run.measurements) {
    if(m.histogram_counts.reduce((a,b)=>a+b,0)!==m.count)throw new ContractError('histogram-count');
    const qs=[m.p50_ms,m.p95_ms,m.p99_ms];
    if(m.count===0?qs.some(q=>q!==null):qs.some(q=>q===null)||m.p50_ms!>m.p95_ms!||m.p95_ms!>m.p99_ms!)throw new ContractError('quantiles-invalid');
  }
}
const safe=(n:unknown):n is number=>typeof n==='number'&&Number.isSafeInteger(n)&&n>=0;
export function parseSnapshotReply(reply:unknown,m:Manifest):{tag:string;now_ms?:number;epoch?:number;start_ms?:number;end_ms?:number} {
  if(!Array.isArray(reply))throw new ContractError('replay-reply-invalid');
  if(reply.length===1&&['RUN_UNAVAILABLE','CLOCK_UNSAFE'].includes(reply[0] as string))return {tag:reply[0] as string};
  if(reply.length!==8||reply[0]!=='SNAPSHOT'||reply[1]!==m.run_id||reply[2]!==m.token_key_id||reply[3]!==configurationDigest(m)||!reply.slice(4).every(safe))throw new ContractError('replay-reply-invalid');
  const b=epochAt(m,reply[4] as number);
  if(reply[5]!==b.epoch||reply[6]!==b.start_ms||reply[7]!==b.end_ms)throw new ContractError('replay-reply-invalid');
  return {tag:'SNAPSHOT',now_ms:reply[4] as number,...{epoch:b.epoch,start_ms:b.start_ms,end_ms:b.end_ms}};
}
export function parseClaimReply(reply:unknown,expectedExpiry:number):{tag:string;expiry_ms?:number} {
  if(!Array.isArray(reply))throw new ContractError('replay-reply-invalid');
  if(reply.length===2&&reply[0]==='CLAIMED'&&safe(reply[1])&&reply[1]===expectedExpiry)return {tag:'CLAIMED',expiry_ms:reply[1]};
  if(reply.length===1&&['ALREADY_SPENT','EPOCH_CLOSED','RUN_UNAVAILABLE','CLOCK_UNSAFE'].includes(reply[0] as string))return {tag:reply[0] as string};
  throw new ContractError('replay-reply-invalid');
}
