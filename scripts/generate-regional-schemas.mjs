import { readFileSync, writeFileSync } from 'node:fs';
const base = new URL('../src/contracts/', import.meta.url);
const p = JSON.parse(readFileSync(new URL('lib/regional-v1.json', base), 'utf8'));
const c = value => ({const:value});
const integer = (minimum=0, maximum=Number.MAX_SAFE_INTEGER) => ({type:'integer',minimum,maximum});
const text = (maxLength, pattern, minLength=1) => ({type:'string',minLength,maxLength,...(pattern?{pattern}:{})});
const hex = n => text(n,`^[0-9a-f]{${n}}$`,n);
const b64 = max => text(max,'^[A-Za-z0-9_-]+$');
const obj = properties => ({type:'object',properties,required:Object.keys(properties),additionalProperties:false});
const either = (...oneOf) => ({oneOf});
const envelope = fields => obj({contract_version:c(p.contract_version),...fields});
const policy = either(...p.profiles.map(profile => envelope({
  schema_version:c(1),run_id:hex(32),baseline_config_digest:hex(64),profile:c(profile),
  window_start_ms:integer(1),window_end_ms:integer(1),quota:c(p.quota),
  admitted_entitlements:c(p.admitted_entitlements),resource_id:c(p.resource_id),method:c(p.method),url:c(p.url),
  type2_key_id:profile.startsWith('type2-')?hex(64):c(null),
  arc_key_id:profile==='arc'?hex(64):c(null),
  arc_implementation_revision:profile==='arc'?hex(40):c(null),
  arc_tag_encoding:profile==='arc'?c(p.arc_tag_encoding):c(null)
})));
const bound = {run_id:hex(32),policy_digest:hex(64)};
const nonce = envelope({...bound,token_hash:hex(64),holder_key_hash:hex(64),
  issued_ms:integer(1),expires_ms:integer(1),random_b64url:text(43,'^[A-Za-z0-9_-]{43}$',43)});
const proof = envelope({policy_digest:hex(64),public_key_spki_b64url:text(122,'^[A-Za-z0-9_-]{122}$',122),
  nonce:obj({body:nonce,mac:hex(64)}),signature_b64url:text(86,'^[A-Za-z0-9_-]{86}$',86)});
const rpcBase = {...bound,request_id:hex(32),service_incarnation:hex(32)};
const request = either(
  envelope({...rpcBase,operation:c('issue'),grant_id:hex(32),blinded_request_b64url:b64(32768)}),
  envelope({...rpcBase,operation:c('verify'),presentation_b64url:b64(32768)})
);
const replyBase = {...rpcBase,request_digest:hex(64)};
const codes=['invalid-input','invalid-proof','wrong-policy','grant-used','window-closed','unavailable'];
const reply = either(
  envelope({...replyBase,operation:c('issue'),status:c('issued'),credential_response_b64url:b64(32768)}),
  envelope({...replyBase,operation:c('verify'),status:c('verified'),spend_tag_b64url:text(44,'^[A-Za-z0-9_-]{44}$',44)}),
  ...['issue','verify'].map(operation=>envelope({...replyBase,operation:c(operation),status:c('refused'),code:{enum:codes}}))
);
const publicBase={contract_version:c(p.contract_version),policy_digest:hex(64)};
const spki=text(122,'^[A-Za-z0-9_-]{122}$',122);
const nonceEnvelope=obj({body:nonce,mac:hex(64)});
const bootstrap=envelope({run_id:hex(32),service_incarnation:hex(32),arc_implementation_revision:hex(40),
  issuer_params_b64url:text(132,'^[A-Za-z0-9_-]{132}$',132),arc_key_id:hex(64)});
const publicCase=(route,body)=>obj({route:c(route),body});
const enrollment=profile=>obj({...publicBase,profile:c(profile),enrollment_voucher_b64url:text(43,'^[A-Za-z0-9_-]{43}$',43),
  blinded_requests_b64url:{type:'array',minItems:profile==='arc'?1:5,maxItems:profile==='arc'?1:5,items:b64(profile==='arc'?32768:346)}});
const publicRequests=either(
  ...['arc','type2-bearer','type2-holder'].map(profile=>publicCase('enroll',enrollment(profile))),
  publicCase('arc-redeem',obj({...publicBase,presentation_b64url:b64(32768)})),
  publicCase('holder-challenge',obj({...publicBase,public_key_spki_b64url:spki})),
  publicCase('holder-nonce',obj({...publicBase,token_hash:hex(64),public_key_spki_b64url:spki})),
  publicCase('holder-redeem',obj({...publicBase,token_b64url:text(472,'^[A-Za-z0-9_-]{472}$',472),proof}))
);
const publicResponses=either(
  ...['arc','type2-bearer','type2-holder'].map(profile=>publicCase('enroll',obj({...publicBase,profile:c(profile),
    responses_b64url:{type:'array',minItems:profile==='arc'?1:5,maxItems:profile==='arc'?1:5,items:b64(profile==='arc'?32768:342)}}))),
  publicCase('holder-challenge',obj({...publicBase,challenge_b64url:b64(1024),token_key_spki_b64url:b64(1024)})),
  publicCase('holder-nonce',nonceEnvelope),
  publicCase('arc-directory',obj({...publicBase,arc_key_id:hex(64),arc_implementation_revision:hex(40),
    issuer_params_b64url:text(132,'^[A-Za-z0-9_-]{132}$',132)}))
);
const schemas = {
  'regional-policy-v1.json':policy,
  'regional-holder-nonce-v1.json':nonce,
  'regional-holder-proof-v1.json':proof,
  'regional-arc-request-v1.json':request,
  'regional-arc-response-v1.json':reply,
  'regional-arc-bootstrap-v1.json':bootstrap,
  'regional-public-request-v1.json':publicRequests,
  'regional-public-response-v1.json':publicResponses
};
let drift=false;
for(const [name,body] of Object.entries(schemas)) {
  const output=JSON.stringify({$schema:'http://json-schema.org/draft-07/schema#',$id:`https://tokenforge.invalid/contracts/${name}`,...body},null,2)+'\n';
  const path=new URL(`schemas/${name}`,base);
  if(process.argv.includes('--check')) {
    let actual;try{actual=readFileSync(path,'utf8');}catch{actual='';}
    if(actual!==output){process.stderr.write(`Regional schema drift: ${name}\n`);drift=true;}
  } else writeFileSync(path,output);
}
if(drift)process.exitCode=1;
