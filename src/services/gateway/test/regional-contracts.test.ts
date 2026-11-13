import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Ajv } from 'ajv';
import golden from '../../../contracts/fixtures/regional-golden.json' with {type:'json'};
import baseline from '../../../contracts/fixtures/policy-golden.json' with {type:'json'};
import { configurationDigest, hex, sha256, type Manifest } from '../../../contracts/lib/index.ts';
import { conforms, type Schema } from '../../../contracts/lib/schema.ts';
import { REGIONAL, validateRegionalPolicy, regionalPolicyDigest, requireRegionalWindow, regionalContext,
  holderKeyHash, holderContextInput, holderNonceMacInput, holderProofInput, validateHolderProof, validateHolderNonce,
  validateArcRequest, validateArcResponse, arcSpendId, arcRpcMacInput, encodeRegionalFrame,
  type HolderProof, type RegionalPolicy } from '../../../contracts/lib/regional.ts';

const holder=validateRegionalPolicy(golden.holder_policy),arc=validateRegionalPolicy(golden.arc_policy);
const token=new Uint8Array(354);
const copy=<T>(value:T):T=>structuredClone(value);
const mac=(label:string,input:Uint8Array)=>createHmac('sha256',createHash('sha256').update(label).digest()).update(input).digest('hex');

test('independent Python framing, HMAC, public-key and spend fixtures match byte-for-byte',()=>{
  assert.equal(regionalPolicyDigest(holder),golden.holder_policy_digest);
  assert.equal(regionalPolicyDigest(arc),golden.arc_policy_digest);
  assert.equal(holderKeyHash(golden.public_key_spki_b64url),golden.signed_nonce.body.holder_key_hash);
  assert.equal(hex(sha256(token)),golden.token_hash);
  const context=holderContextInput(holder,golden.public_key_spki_b64url);
  assert.equal(hex(context),golden.holder_context_input_hex);
  assert.equal(mac('TokenForge-public-fixture-context-key',context),golden.holder_context_hex);
  const n=golden.signed_nonce;
  assert.equal(hex(holderNonceMacInput(n.body)),golden.holder_nonce_input_hex);
  assert.equal(mac('TokenForge-public-fixture-nonce-key',holderNonceMacInput(n.body)),n.mac);
  assert.equal(hex(holderProofInput(holder,token,golden.public_key_spki_b64url,n,100011)),golden.holder_proof_input_hex);
  const request=validateArcRequest(golden.arc_request,arc),reply=validateArcResponse(golden.arc_response,request,arc);
  const ri=arcRpcMacInput('request','verify',request),si=arcRpcMacInput('response','verify',reply);
  assert.equal(hex(ri),golden.arc_rpc_input_hex);assert.equal(hex(si),golden.arc_reply_input_hex);
  assert.equal(mac('TokenForge-public-fixture-verify-key',ri),golden.arc_request_mac);
  assert.equal(mac('TokenForge-public-fixture-verify-key',si),golden.arc_reply_mac);
  assert.notDeepEqual(ri,si);
  assert.equal(Buffer.from(encodeRegionalFrame(request,golden.arc_request_mac)).toString(),golden.arc_request_frame);
  assert.equal(arcSpendId(arc,reply.status==='verified'?reply.spend_tag_b64url:''),golden.arc_spend_id);
  for(const kind of ['context','arc_request_context','arc_presentation_context'] as const)
    assert.equal(hex(regionalContext(arc,kind)),golden.contexts[kind]);
});

test('policy cannot change quota/profile/key layout or silently reinterpret baseline epoch',()=>{
  const variants=[{quota:6},{profile:'anything'},{extra:true},{window_end_ms:160001},{window_start_ms:0},
    {window_end_ms:Number.MAX_SAFE_INTEGER,window_start_ms:Number.MAX_SAFE_INTEGER-60000},
    {type2_key_id:null},{arc_key_id:'1'.repeat(64)},{contract_version:'TF-PS024-1.0.0'}];
  for(const change of variants)assert.throws(()=>validateRegionalPolicy({...holder,...change}));
  const m=baseline.manifest as Manifest;
  const p={...holder,run_id:m.run_id,baseline_config_digest:configurationDigest(m),
    type2_key_id:m.token_key_id,window_start_ms:m.run_start_ms,window_end_ms:m.run_start_ms+60000};
  assert.doesNotThrow(()=>validateRegionalPolicy(p,m));
  assert.throws(()=>validateRegionalPolicy({...p,baseline_config_digest:'0'.repeat(64)},m));
  assert.throws(()=>validateRegionalPolicy({...p,type2_key_id:'0'.repeat(64)},m));
  assert.throws(()=>validateRegionalPolicy({...p,window_start_ms:m.run_start_ms+600000,window_end_ms:m.run_start_ms+660000},m));
  assert.equal(m.epoch_ms,600000);assert.equal(REGIONAL.window_ms,60000);
  assert.throws(()=>{REGIONAL.quota=999;});
});

test('fixed window and nonce boundaries have no retention acceptance grace',()=>{
  assert.doesNotThrow(()=>requireRegionalWindow(holder,100000));
  assert.doesNotThrow(()=>requireRegionalWindow(holder,159999));
  for(const now of [99999,160000,NaN,Infinity,100000.5])assert.throws(()=>requireRegionalWindow(holder,now));
  const n=golden.signed_nonce.body;
  assert.doesNotThrow(()=>validateHolderNonce(n,holder,110009));
  assert.throws(()=>validateHolderNonce(n,holder,110010));
  for(const change of [{issued_ms:100012},{expires_ms:110011},{expires_ms:100010},
    {run_id:'0'.repeat(32)},{policy_digest:'0'.repeat(64)},{extra:'no'},
    {random_b64url:n.random_b64url.slice(0,-1)+'_' }])
    assert.throws(()=>validateHolderNonce({...n,...change},holder,100011));
  assert.throws(()=>validateHolderNonce(n,{...holder,profile:'arc'} as RegionalPolicy,100011));
});

test('holder proof uses canonical real P-256 signing bytes and request/token/key bindings',()=>{
  const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const spki=pair.publicKey.export({format:'der',type:'spki'}).toString('base64url');
  const n=copy(golden.signed_nonce);n.body.holder_key_hash=holderKeyHash(spki);
  n.mac=mac('TokenForge-public-fixture-nonce-key',holderNonceMacInput(n.body));
  const input=holderProofInput(holder,token,spki,n,100011);
  const signature=sign('sha256',input,{key:pair.privateKey,dsaEncoding:'ieee-p1363'});
  const proof:HolderProof={contract_version:REGIONAL.contract_version,policy_digest:regionalPolicyDigest(holder),
    public_key_spki_b64url:spki,nonce:n,signature_b64url:signature.toString('base64url')};
  assert.doesNotThrow(()=>validateHolderProof(proof,holder,token,100011));
  assert.equal(signature.length,64);
  assert.equal(verify('sha256',input,{key:pair.publicKey,dsaEncoding:'ieee-p1363'},signature),true);
  assert.equal(verify('sha256',Uint8Array.from([...input,0]),{key:pair.publicKey,dsaEncoding:'ieee-p1363'},signature),false);
  for(const changed of [{...proof,policy_digest:'0'.repeat(64)}, {...proof,signature_b64url:proof.signature_b64url+'='},
    {...proof,public_key_spki_b64url:golden.public_key_spki_b64url}, {...proof,extra:true}])
    assert.throws(()=>validateHolderProof(changed,holder,token,100011));
  assert.throws(()=>holderProofInput(holder,new Uint8Array(353),spki,n,100011));
  const changedToken=token.slice();changedToken[0]=1;
  assert.throws(()=>holderProofInput(holder,changedToken,spki,n,100011));
  assert.throws(()=>holderKeyHash(spki+'='));
  const other=generateKeyPairSync('ec',{namedCurve:'secp384r1'});
  assert.throws(()=>holderKeyHash(other.publicKey.export({format:'der',type:'spki'}).toString('base64url')));
  // Structural validation deliberately does not establish token/signature/MAC validity.
  assert.doesNotThrow(()=>validateHolderProof({...proof,signature_b64url:Buffer.alloc(64).toString('base64url')},holder,token,100011));
});

test('ARC replies cannot be swapped across operations, policies, requests or service incarnations',()=>{
  const request=validateArcRequest(golden.arc_request,arc);
  for(const change of [{request_id:'f'.repeat(32)},{service_incarnation:'f'.repeat(32)},
    {request_digest:'0'.repeat(64)},{policy_digest:'0'.repeat(64)},{run_id:'0'.repeat(32)},
    {status:'issued',operation:'issue'},{spend_tag_b64url:Buffer.alloc(33,0).toString('base64url')},
    {spend_tag_b64url:Buffer.concat([Buffer.from([2]),Buffer.alloc(32,255)]).toString('base64url')},
    {spend_tag_b64url:golden.arc_response.spend_tag_b64url+'='},{extra:true}])
    assert.throws(()=>validateArcResponse({...golden.arc_response,...change},request,arc));
  for(const blob of ['AQID=','A','_'.repeat(32769)])
    assert.throws(()=>validateArcRequest({...request,presentation_b64url:blob},arc));
  assert.throws(()=>arcRpcMacInput('request','issue',request));
  const changed=validateRegionalPolicy({...arc,run_id:'f'.repeat(32)});
  assert.notEqual(arcSpendId(changed,golden.arc_response.spend_tag_b64url),golden.arc_spend_id);
  assert.throws(()=>validateArcRequest(golden.arc_request,holder));
  const full=validateArcRequest({...request,presentation_b64url:Buffer.alloc(24576,1).toString('base64url')},arc);
  assert.ok(encodeRegionalFrame(full,'0'.repeat(64)).length<65536);
  assert.throws(()=>encodeRegionalFrame(full,'bad'));
});

test('regional strict schemas agree with independent Ajv on representative positive/negative messages',()=>{
  const samples:Record<string,unknown>={
    'regional-policy-v1.json':golden.arc_policy,'regional-holder-nonce-v1.json':golden.signed_nonce.body,
    'regional-arc-request-v1.json':golden.arc_request,'regional-arc-response-v1.json':golden.arc_response,
    'regional-holder-proof-v1.json':{contract_version:REGIONAL.contract_version,policy_digest:golden.holder_policy_digest,
      public_key_spki_b64url:golden.public_key_spki_b64url,nonce:golden.signed_nonce,signature_b64url:Buffer.alloc(64).toString('base64url')}
  };
  for(const [name,sample] of Object.entries(samples)) {
    const schema=JSON.parse(readFileSync(new URL('../../../contracts/schemas/'+name,import.meta.url),'utf8')) as Schema;
    const validate=new Ajv({strict:true}).compile(schema);
    for(const value of [sample,{...(sample as object),extra:true},{},null]) {
      assert.equal(conforms(schema,value),validate(value));
      assert.equal(conforms(schema,value),value===sample);
    }
  }
});
