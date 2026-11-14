import test from 'node:test';
import assert from 'node:assert/strict';
import fixture from '../../../contracts/fixtures/regional-golden.json' with {type:'json'};
import params from '../../arc/fixtures/public-parameters.json' with {type:'json'};
import { canonicalJson } from '../../../contracts/lib/index.ts';
import { REGIONAL, regionalPolicyDigest, validateRegionalPolicy } from '../../../contracts/lib/regional.ts';
import { decodeCanonicalRegionalJson, decodeRegionalPublicRequest, validateArcBootstrap,
  validateRegionalPublicResponse } from '../../../contracts/lib/regional-wire.ts';

test('ARC bootstrap binds public parameters to expected corrected source, key digest and run',()=>{
  const value={contract_version:REGIONAL.contract_version,run_id:fixture.arc_policy.run_id,service_incarnation:'1'.repeat(32),
    arc_implementation_revision:'2'.repeat(40),issuer_params_b64url:params.issuer_params_b64url,arc_key_id:params.arc_key_id};
  const expected={run_id:value.run_id,arc_implementation_revision:value.arc_implementation_revision};
  assert.doesNotThrow(()=>validateArcBootstrap(value,expected));
  for(const change of [{arc_key_id:'0'.repeat(64)},{arc_implementation_revision:'3'.repeat(40)},
    {run_id:'0'.repeat(32)},{issuer_params_b64url:Buffer.alloc(99).toString('base64url')},{extra:true}])
    assert.throws(()=>validateArcBootstrap({...value,...change},expected));
});

test('public canonical request parser rejects duplicate fields, trailing data, foreign profiles and unsafe encodings',()=>{
  const p=validateRegionalPolicy(fixture.holder_policy),body={contract_version:REGIONAL.contract_version,
    policy_digest:regionalPolicyDigest(p),public_key_spki_b64url:fixture.public_key_spki_b64url};
  const bytes=Buffer.from(canonicalJson(body));
  assert.doesNotThrow(()=>decodeRegionalPublicRequest('holder-challenge',bytes,p));
  for(const text of [JSON.stringify(body,null,2),canonicalJson(body)+'\n',canonicalJson(body)+'{}',
    canonicalJson(body).replace('"contract_version":','"contract_version":"bad","contract_version":')])
    assert.throws(()=>decodeRegionalPublicRequest('holder-challenge',Buffer.from(text),p));
  assert.throws(()=>decodeCanonicalRegionalJson(Uint8Array.from([0xff])));
  assert.throws(()=>decodeCanonicalRegionalJson(Buffer.alloc(65537,32)));
  assert.throws(()=>decodeRegionalPublicRequest('holder-challenge',bytes,validateRegionalPolicy(fixture.arc_policy)));
  assert.throws(()=>decodeRegionalPublicRequest('holder-challenge',Buffer.from(canonicalJson({...body,extra:true})),p));
});

test('ARC directory and enrollment counts preserve server-selected profile and entitlement budget',()=>{
  const p=validateRegionalPolicy({...fixture.arc_policy,arc_key_id:params.arc_key_id});
  const directory={contract_version:REGIONAL.contract_version,policy_digest:regionalPolicyDigest(p),
    arc_key_id:p.arc_key_id,arc_implementation_revision:p.arc_implementation_revision,issuer_params_b64url:params.issuer_params_b64url};
  assert.doesNotThrow(()=>validateRegionalPublicResponse('arc-directory',directory,p));
  assert.throws(()=>validateRegionalPublicResponse('arc-directory',{...directory,arc_key_id:'0'.repeat(64)},p));
  const enroll={contract_version:REGIONAL.contract_version,policy_digest:regionalPolicyDigest(p),profile:'arc',
    enrollment_voucher_b64url:Buffer.alloc(32,7).toString('base64url'),blinded_requests_b64url:['AQID']};
  assert.doesNotThrow(()=>decodeRegionalPublicRequest('enroll',Buffer.from(canonicalJson(enroll)),p));
  assert.throws(()=>decodeRegionalPublicRequest('enroll',Buffer.from(canonicalJson({...enroll,blinded_requests_b64url:['AQID','AQID']})),p));
  const t=validateRegionalPolicy({...fixture.holder_policy,profile:'type2-bearer'});
  const type2={...enroll,profile:'type2-bearer',policy_digest:regionalPolicyDigest(t),blinded_requests_b64url:Array(5).fill(Buffer.alloc(259).toString('base64url'))};
  assert.doesNotThrow(()=>decodeRegionalPublicRequest('enroll',Buffer.from(canonicalJson(type2)),t));
  assert.throws(()=>decodeRegionalPublicRequest('enroll',Buffer.from(canonicalJson({...type2,blinded_requests_b64url:type2.blinded_requests_b64url.slice(1)})),t));
});
