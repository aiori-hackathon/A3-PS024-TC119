import { createHmac, ECDH, timingSafeEqual } from 'node:crypto';
import { assertSchema, ContractError, deepFreeze, type Schema } from './schema.ts';
import { canonicalJson, decodeBase64Url, hex, sha256, PROTOCOL } from './index.ts';
import { REGIONAL, arcRpcMacInput, regionalPolicyDigest, validateArcRequest, validateArcResponse,
  validateRegionalPolicy, holderKeyHash, type RegionalPolicy, type ArcRequest, type ArcResponse } from './regional.ts';
import bootstrapSchema from '../schemas/regional-arc-bootstrap-v1.json' with {type:'json'};
import publicRequestSchema from '../schemas/regional-public-request-v1.json' with {type:'json'};
import publicResponseSchema from '../schemas/regional-public-response-v1.json' with {type:'json'};

export type ArcBootstrap={contract_version:string;run_id:string;service_incarnation:string;
  arc_implementation_revision:string;issuer_params_b64url:string;arc_key_id:string};
export type RegionalPublicRoute='enroll'|'arc-redeem'|'holder-challenge'|'holder-nonce'|'holder-redeem';
/** RFC 9577 Type2 challenge for the one configured issuer/origin, with a supplied authenticated context. */
export function regionalType2Challenge(context:Uint8Array):Uint8Array{
  if(!(context instanceof Uint8Array)||context.length!==32)throw new ContractError('regional-context-size');
  const issuer=Buffer.from(PROTOCOL.issuer_name,'ascii'),origin=Buffer.from(PROTOCOL.origin_name,'ascii');
  const type=Buffer.alloc(2);type.writeUInt16BE(PROTOCOL.token_type);
  const il=Buffer.alloc(2);il.writeUInt16BE(issuer.length);const ol=Buffer.alloc(2);ol.writeUInt16BE(origin.length);
  return Uint8Array.from(Buffer.concat([type,il,issuer,Buffer.from([32]),Buffer.from(context),ol,origin]));
}
function fail():never{throw new ContractError('regional-wire-invalid');}
function binary(value:string,max:number):Uint8Array{
  if(typeof value!=='string'||value.length>Math.ceil(max*4/3)||!/^[A-Za-z0-9_-]+$/.test(value))return fail();
  const bytes=Buffer.from(value,'base64url');
  if(!bytes.length||bytes.length>max||bytes.toString('base64url')!==value)return fail();
  return Uint8Array.from(bytes);
}
export function validateArcBootstrap(value:unknown,expected:{run_id:string;arc_implementation_revision:string}):ArcBootstrap{
  assertSchema(bootstrapSchema as Schema,value);const b=value as ArcBootstrap;
  if(b.run_id!==expected.run_id||b.arc_implementation_revision!==expected.arc_implementation_revision)return fail();
  const bytes=decodeBase64Url(b.issuer_params_b64url,REGIONAL.arc_issuer_params_bytes,false);
  if(hex(sha256(bytes))!==b.arc_key_id)return fail();
  try{
    for(let i=0;i<99;i+=33){
      const point=Buffer.from(bytes.subarray(i,i+33));
      const canonical=ECDH.convertKey(point,'prime256v1',undefined,undefined,'compressed');
      if(![2,3].includes(point[0]!)||typeof canonical==='string'||!point.equals(canonical))return fail();
    }
  }catch{return fail();}
  return deepFreeze(structuredClone(b));
}
/** Enforce canonical raw bytes, so duplicate keys/trailing bytes cannot disappear during JSON.parse. */
export function decodeCanonicalRegionalJson(wire:Uint8Array,newline=false):unknown{
  if(!(wire instanceof Uint8Array)||wire.length===0||wire.length>REGIONAL.rpc_frame_max_bytes)return fail();
  try{
    const bytes=Uint8Array.from(wire),text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
    if(newline&&!text.endsWith('\n'))return fail();
    const value:unknown=JSON.parse(newline?text.slice(0,-1):text);
    const expected=Buffer.from(canonicalJson(value)+(newline?'\n':''),'utf8');
    if(!expected.equals(Buffer.from(bytes)))return fail();
    return value;
  }catch{return fail();}
}
export function regionalMac(key:Uint8Array,input:Uint8Array):string{
  if(!(key instanceof Uint8Array)||key.length!==32)return fail();
  return createHmac('sha256',key).update(input).digest('hex');
}
export function checkRegionalMac(key:Uint8Array,input:Uint8Array,provided:string):boolean{
  if(typeof provided!=='string'||!/^[0-9a-f]{64}$/.test(provided))return false;
  return timingSafeEqual(Buffer.from(regionalMac(key,input),'hex'),Buffer.from(provided,'hex'));
}
export function authenticateArcResponse(wire:Uint8Array,request:ArcRequest,p:RegionalPolicy,key:Uint8Array):ArcResponse{
  const value=decodeCanonicalRegionalJson(wire,true);
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!=='body,mac')return fail();
  const frame=value as {body:ArcResponse;mac:string};
  // Schema bounds apply before MAC work; point validation and exact request binding follow authentication.
  const input=arcRpcMacInput('response',request.operation,frame.body);
  if(!checkRegionalMac(key,input,frame.mac))return fail();
  return validateArcResponse(frame.body,validateArcRequest(request,p),p);
}
export function validateRegionalPublicRequest(route:RegionalPublicRoute,value:unknown,p:RegionalPolicy):Record<string,unknown>{
  validateRegionalPolicy(p);assertSchema(publicRequestSchema as Schema,{route,body:value});
  const body=value as Record<string,unknown>;
  if(body['policy_digest']!==regionalPolicyDigest(p))return fail();
  if(route==='enroll'){
    if(p.profile==='ip'||body['profile']!==p.profile)return fail();
    decodeBase64Url(body['enrollment_voucher_b64url'] as string,32,false);
    for(const b of body['blinded_requests_b64url'] as string[]){
      if(p.profile==='arc')binary(b,REGIONAL.arc_blob_max_bytes);else decodeBase64Url(b,259,false);
    }
  }else if(route==='arc-redeem'){
    if(p.profile!=='arc')return fail();binary(body['presentation_b64url'] as string,REGIONAL.arc_blob_max_bytes);
  }else{
    if(p.profile!=='type2-holder')return fail();
    if(route==='holder-redeem'){
      decodeBase64Url(body['token_b64url'] as string,354,false);
      const proof=body['proof'] as {policy_digest:string;public_key_spki_b64url:string;signature_b64url:string};
      if(proof.policy_digest!==regionalPolicyDigest(p))return fail();
      holderKeyHash(proof.public_key_spki_b64url);decodeBase64Url(proof.signature_b64url,64,false);
    }else holderKeyHash(body['public_key_spki_b64url'] as string);
  }
  return deepFreeze(structuredClone(body));
}
export function decodeRegionalPublicRequest(route:RegionalPublicRoute,wire:Uint8Array,p:RegionalPolicy):Record<string,unknown>{
  return validateRegionalPublicRequest(route,decodeCanonicalRegionalJson(wire),p);
}
export function validateRegionalPublicResponse(route:'enroll'|'holder-challenge'|'holder-nonce'|'arc-directory',value:unknown,p:RegionalPolicy):void{
  assertSchema(publicResponseSchema as Schema,{route,body:value});const body=value as Record<string,unknown>;
  const digest=route==='holder-nonce'?(body['body'] as Record<string,unknown>)['policy_digest']:body['policy_digest'];
  if(digest!==regionalPolicyDigest(p))return fail();
  if(route==='arc-directory'){
    if(p.profile!=='arc'||body['arc_key_id']!==p.arc_key_id||body['arc_implementation_revision']!==p.arc_implementation_revision)return fail();
    validateArcBootstrap({contract_version:REGIONAL.contract_version,run_id:p.run_id,service_incarnation:'0'.repeat(32),
      ...Object.fromEntries(['arc_key_id','arc_implementation_revision','issuer_params_b64url'].map(k=>[k,body[k]]))},
      {run_id:p.run_id,arc_implementation_revision:p.arc_implementation_revision!});
  }else if(route==='enroll'){
    if(body['profile']!==p.profile||p.profile==='ip')return fail();
    for(const b of body['responses_b64url'] as string[])p.profile==='arc'?binary(b,REGIONAL.arc_blob_max_bytes):decodeBase64Url(b,256,false);
  }else{
    if(p.profile!=='type2-holder')return fail();
    if(route==='holder-challenge'){
      const challenge=binary(body['challenge_b64url'] as string,1024),offset=5+PROTOCOL.issuer_name.length;
      if(!Buffer.from(challenge).equals(Buffer.from(regionalType2Challenge(challenge.subarray(offset,offset+32)))))return fail();
      if(hex(sha256(binary(body['token_key_spki_b64url'] as string,768)))!==p.type2_key_id)return fail();
    }else{
      const n=body['body'] as Record<string,unknown>;
      if(n['run_id']!==p.run_id||typeof n['issued_ms']!=='number'||typeof n['expires_ms']!=='number'
        ||n['issued_ms']<p.window_start_ms||n['expires_ms']>p.window_end_ms||n['expires_ms']<=n['issued_ms']
        ||n['expires_ms']-n['issued_ms']>REGIONAL.nonce_lifetime_ms)return fail();
      decodeBase64Url(n['random_b64url'] as string,32,false);
    }
  }
}
