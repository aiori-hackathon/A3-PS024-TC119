import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { Ajv } from 'ajv';
import golden from '../../../contracts/fixtures/policy-golden.json' with {type:'json'};
import manifestSchema from '../../../contracts/schemas/run-manifest-v1.json' with {type:'json'};
import requestSchema from '../../../contracts/schemas/control-request-v1.json' with {type:'json'};
import replySchema from '../../../contracts/schemas/control-response-v1.json' with {type:'json'};
import reportSchema from '../../../contracts/schemas/report-v1.schema.json' with {type:'json'};
import { conforms, assertSupportedSchema, type Schema } from '../../../contracts/lib/schema.ts';
import {
  CONTRACT_VERSION,PROTOCOL,canonicalJson,configurationDigest,validateManifest,makeManifest,
  epochAt,epochBounds,contextInput,redemptionContext,challengeBytes,authenticatorInput,spendId,voucherDigest,
  fromHex,hex,sha256,libraryBytes,encodeBase64Url,decodeBase64Url,tokenWire,validateControlRequest,
  validateControlResponse,validateReport,parseSnapshotReply,parseClaimReply,
} from '../../../contracts/lib/index.ts';
const m=validateManifest(golden.manifest);
const copy=<T>(x:T):T=>structuredClone(x);
const nonce=fromHex(golden.nonce_hex,32);
const ajv=new Ajv({strict:true,allErrors:true});

test('all generated schemas compile under strict independent Ajv',()=>{
  const url=new URL('../../../contracts/schemas/',import.meta.url);
  for(const name of readdirSync(url)) {
    const schema=JSON.parse(readFileSync(new URL(name,url),'utf8'));
    assert.doesNotThrow(()=>new Ajv({strict:true}).compile(schema));
  }
});
test('runtime schema subset fails on unsupported keywords and protocol values are immutable',()=>{
  assert.throws(()=>assertSupportedSchema({type:'object',patternProperties:{}} as unknown as Schema));
  assert.throws(()=>assertSupportedSchema({oneOf:[{const:1}],type:'number'}));
  assert.throws(()=>{PROTOCOL.gateway_profiles.B1.workers=99;});
});
test('Python-derived complete policy golden vector matches TS byte-for-byte',()=>{
  assert.equal(CONTRACT_VERSION,'TF-PS024-1.0.0');
  assert.equal(canonicalJson(m),golden.canonical_manifest);
  assert.equal(configurationDigest(m),golden.config_digest);
  assert.equal(hex(contextInput(m,golden.epoch)),golden.context_input_hex);
  assert.equal(hex(redemptionContext(m,golden.epoch)),golden.redemption_context_hex);
  assert.equal(hex(challengeBytes(m,golden.epoch)),golden.challenge_hex);
  assert.equal(hex(sha256(challengeBytes(m,golden.epoch))),golden.challenge_digest_hex);
  const input=authenticatorInput(nonce,sha256(challengeBytes(m,golden.epoch)),fromHex(m.token_key_id,32));
  assert.equal(hex(input),golden.auth_input_hex);
  assert.equal(spendId(input),golden.spend_id);
  assert.equal(voucherDigest(fromHex(golden.voucher_hex,32)),golden.voucher_digest);
  assert.equal(fromHex(m.token_key_id,32).at(-1),golden.truncated_token_key_id);
});
test('manifest profile builder reproduces fixture without copied constants',()=>{
  assert.deepEqual(makeManifest({run_id:m.run_id,run_start_ms:m.run_start_ms,token_key_spki_b64url:m.token_key_spki_b64url,
    snapshot_script_sha1:m.snapshot_script_sha1,claim_script_sha1:m.claim_script_sha1,client_profile:'security'}),m);
  const b0=makeManifest({run_id:m.run_id,run_start_ms:m.run_start_ms,token_key_spki_b64url:m.token_key_spki_b64url,
    snapshot_script_sha1:m.snapshot_script_sha1,claim_script_sha1:m.claim_script_sha1,gateway_profile:'B0'});
  assert.equal(b0.limits.gateway.workers,1);
  assert.equal(b0.limits.gateway.active_flows_per_worker,1);
});
test('manifest rejects configuration drift, extra secrets, malformed keys and unsafe times',()=>{
  const invalid:unknown[]=[{...m,secret:'do-not-echo'}, {...m,token_type:1}, {...m,run_start_ms:-1},
    {...m,token_key_id:'0'.repeat(64)},{...m,gateway_profile:'B0'}, {...m,inventory_total:129},
    {...m,token_key_spki_b64url:m.token_key_spki_b64url+'='},
    {...m,limits:{...m.limits,gateway:{...m.limits.gateway,workers:3}}},
    {...m,run_start_ms:Number.MAX_SAFE_INTEGER}];
  const malformed=new Uint8Array(342);
  invalid.push({...m,token_key_spki_b64url:encodeBase64Url(malformed),token_key_id:hex(sha256(malformed))});
  for(const v of invalid)assert.throws(()=>validateManifest(v));
});
test('canonical digest is order-independent and rejects ambiguous/non-JSON values',()=>{
  assert.equal(configurationDigest({b:2,a:1}),configurationDigest({a:1,b:2}));
  assert.notEqual(configurationDigest({a:1}),configurationDigest({a:2}));
  for(const v of [NaN,Infinity,-0,-1,1.1,undefined,new Date(),{'é':1},'\n','é',new Array(3)])assert.throws(()=>canonicalJson(v));
  const cycle:Record<string,unknown>={};cycle['self']=cycle;
  assert.throws(()=>canonicalJson(cycle));
});
test('epoch boundary and safe-integer overflow use exact arithmetic',()=>{
  assert.equal(epochAt(m,m.run_start_ms).epoch,0);
  assert.equal(epochAt(m,m.run_start_ms+599999).epoch,0);
  assert.equal(epochAt(m,m.run_start_ms+600000).epoch,1);
  assert.throws(()=>epochAt(m,m.run_start_ms-1));
  assert.throws(()=>epochBounds(m,Number.MAX_SAFE_INTEGER));
  assert.throws(()=>epochBounds(m,-1));
});
test('changed run, scope, key, epoch or nonce changes authorization identity',()=>{
  const original=hex(redemptionContext(m,2));
  for(const changed of [{...m,run_id:'f'.repeat(32)},{...m,resource_scope:'GET /else'},{...m,token_key_id:'0'.repeat(64)}])
    assert.notEqual(hex(redemptionContext(changed,2)),original);
  assert.notEqual(hex(redemptionContext(m,3)),original);
  const input=fromHex(golden.auth_input_hex,98);const altered=Uint8Array.from(input);altered[2]=altered[2]!^1;
  assert.notEqual(spendId(altered),spendId(input));
});
test('standalone byte copies isolate pooled buffers and views before library calls',()=>{
  const backing=Buffer.alloc(512,0xee);const view=backing.subarray(31,63);nonce.forEach((b,i)=>view[i]=b);
  const copied=libraryBytes(view,32);
  assert.equal(copied.byteOffset,0);assert.equal(copied.buffer.byteLength,32);assert.equal(hex(copied),golden.nonce_hex);
  view[0]=255;assert.equal(copied[0],0);
  assert.throws(()=>libraryBytes(view,31));
});
test('strict base64url enforces canonical padding, pad bits and length',()=>{
  const b=Uint8Array.of(0xff);
  assert.equal(encodeBase64Url(b),'_w==');assert.deepEqual(decodeBase64Url('_w==',1),b);
  for(const s of ['_w','_x==','/w==','_w===',' _w==','_w==\n'])assert.throws(()=>decodeBase64Url(s,1));
  assert.deepEqual(decodeBase64Url('_w',1,false),b);
  assert.throws(()=>decodeBase64Url('_w==',1,false));
  assert.throws(()=>decodeBase64Url('A'.repeat(4097)));
});
test('strict wire validation rejects unsupported/truncated/trailing token bytes',()=>{
  const wire=new Uint8Array(354);wire[1]=2;assert.equal(tokenWire(wire).length,354);
  for(const len of [0,353,355,4096])assert.throws(()=>tokenWire(new Uint8Array(len)));
  wire[1]=1;assert.throws(()=>tokenWire(wire));
});
const envelope=(command:string,payload:unknown,initial=false)=>({version:1,request_id:'a'.repeat(32),command,
  run_id:m.run_id,config_digest:initial?null:golden.config_digest,target_incarnation:'b'.repeat(32),payload});
test('control schema and semantic PREPARE reject drift and unbounded provisioning',()=>{
  const prepare=envelope('PREPARE_RUN',{manifest:m,proposed_config_digest:golden.config_digest,role:'gateway',role_config:{}},true);
  assert.doesNotThrow(()=>validateControlRequest(prepare));
  assert.throws(()=>validateControlRequest({...prepare,payload:{...prepare.payload as object,proposed_config_digest:'0'.repeat(64)}}));
  const batch={batch_id:'c'.repeat(32),batch_index:0,expected_total:128,final_batch:true,items:Array<string>(128).fill('d'.repeat(64))};
  assert.doesNotThrow(()=>validateControlRequest(envelope('PROVISION_VOUCHERS',batch)));
  // Duplicate detection is receiver-state behavior, tested when that component exists.
  assert.throws(()=>validateControlRequest(envelope('PROVISION_VOUCHERS',{...batch,items:Array<string>(129).fill('d'.repeat(64))})));
  assert.throws(()=>validateControlRequest(envelope('HEARTBEAT',{seq:0})));
  assert.throws(()=>validateControlRequest(envelope('EXPORT_TOKEN',{})));
  assert.throws(()=>validateControlRequest({...prepare,config_digest:golden.config_digest}));
  assert.throws(()=>validateControlRequest(envelope('PROVISION_CLIENT',{...batch,items:['A'.repeat(42)+'B']})));
});
test('dependency-free schema subset agrees with Ajv for valid/invalid contract messages',()=>{
  for(const [schema,values] of [
    [manifestSchema,[m,{...m,token_type:1},{...m,extra:'secret'},null]],
    [requestSchema,[envelope('HEARTBEAT',{seq:1}),envelope('HEARTBEAT',{seq:'1'}),{...envelope('REPORT',{}),password:'secret'},{}]],
    [replySchema,[{version:1,request_id:'a'.repeat(32),state:'FENCED',run_id:null,config_digest:null,incarnation:'b'.repeat(32),ok:true,result:'FENCED',data:{}},{}]],
    [reportSchema,[{},null]],
  ] as [object,unknown[]][]) {
    const validate=ajv.compile(schema);
    for(const v of values)assert.equal(conforms(schema as Schema,v),validate(v));
  }
});
test('control responses prohibit credential-bearing diagnostics',()=>{
  const r={version:1,request_id:'a'.repeat(32),state:'FAULTED',run_id:m.run_id,config_digest:golden.config_digest,
    incarnation:'b'.repeat(32),ok:false,result:'FAULTED',data:{}};
  assert.doesNotThrow(()=>validateControlResponse(r));
  assert.throws(()=>validateControlResponse({...r,data:{token:'secret'}}));
});
test('replay result adapter validates tag, length, types, identities and bounds',()=>{
  const now=golden.epoch_start_ms+10;
  const good=['SNAPSHOT',m.run_id,m.token_key_id,golden.config_digest,now,2,golden.epoch_start_ms,golden.epoch_end_ms];
  assert.equal(parseSnapshotReply(good,m).epoch,2);
  assert.equal(parseSnapshotReply(['CLOCK_UNSAFE'],m).tag,'CLOCK_UNSAFE');
  for(const bad of [true,'SNAPSHOT',[],[...good,1],good.map((v,i)=>i===3?'0'.repeat(64):v),good.map((v,i)=>i===4?String(v):v),good.map((v,i)=>i===5?1:v)])assert.throws(()=>parseSnapshotReply(bad,m));
  const expiry=golden.epoch_end_ms+30000;
  assert.equal(parseClaimReply(['CLAIMED',expiry],expiry).tag,'CLAIMED');
  for(const tag of ['ALREADY_SPENT','EPOCH_CLOSED','RUN_UNAVAILABLE','CLOCK_UNSAFE'])assert.equal(parseClaimReply([tag],expiry).tag,tag);
  for(const bad of [true,'OK',['CLAIMED'],['CLAIMED',String(expiry)],['CLAIMED',expiry-1],['ALREADY_SPENT',1],{ok:'CLAIMED'}])assert.throws(()=>parseClaimReply(bad,expiry));
});
test('an empty or secret-bearing report cannot claim overall PASS',()=>{
  const report={schema_version:1,contract_version:CONTRACT_VERSION,suite_kind:'demo',suite_id:'a'.repeat(32),created_at_utc:'2026-10-24T00:00:00Z',
    software:{git_commit:'0'.repeat(40),dirty:false,node_version:'24.22.1',dependencies:{privacypass:'0.9.0',blindrsa:'0.4.5'},image_digests:[]},
    environment:{os:'fixture-only',cpu_model:'fixture-only',cpu_count:1,memory_limit_bytes:0,docker_version:'fixture-only',topology:'single-host-private'},
    runs:[],overall_status:'INCONCLUSIVE'};
  assert.doesNotThrow(()=>validateReport(report));
  assert.throws(()=>validateReport({...report,overall_status:'PASS'}));
  assert.throws(()=>validateReport({...report,token:'secret'}));
  const validate=ajv.compile(reportSchema);assert.equal(validate(report),true);
});
