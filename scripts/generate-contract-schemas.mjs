// Deterministic schema generation; JSON files are committed and checked for drift.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const p = JSON.parse(readFileSync(new URL('../src/contracts/protocol-v1.json', import.meta.url)));
const int = (max = Number.MAX_SAFE_INTEGER, min = 0) => ({ type: 'integer', minimum: min, maximum: max });
const str = (max = 256, pattern) => ({ type: 'string', minLength: 1, maxLength: max, ...(pattern ? { pattern } : {}) });
const hex = (n) => str(n, `^[0-9a-f]{${n}}$`);
const c = (value) => ({ const: value });
const choice = (values) => ({ enum: values });
const nil = c(null);
const either = (...oneOf) => ({ oneOf });
const arr = (items, maxItems, minItems = 0) => ({ type: 'array', items, minItems, maxItems });
const obj = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const bool = { type: 'boolean' };
const fixed = (record) => obj(Object.fromEntries(Object.entries(record).map(([k,v]) => [k,c(v)])));
const publicKey = str(1024, '^[A-Za-z0-9_-]+={0,2}$');
const manifest = either(...['B0','B1'].flatMap(gateway => ['demo','security','benchmark'].map(client => obj({
  schema_version:c(1), contract_version:c(p.contract_version), policy_version:c(1),
  run_id:hex(32), run_start_ms:int(Number.MAX_SAFE_INTEGER - p.epoch_ms - p.guard_ms,1),
  epoch_ms:c(p.epoch_ms), guard_ms:c(p.guard_ms), token_type:c(2), token_key_id:hex(64),
  token_key_spki_b64url:publicKey, issuer_name:c(p.issuer_name), origin_name:c(p.origin_name),
  resource_scope:c(p.resource_scope), issuer_request_uri:c(p.issuer_request_uri),
  snapshot_script_sha1:hex(40), claim_script_sha1:hex(40), gateway_profile:c(gateway), client_profile:c(client),
  inventory_total:int(p.client_profiles[client].inventory_max), endpoints:fixed(p.endpoints),
  limits:obj({gateway:fixed({...p.gateway_common,...p.gateway_profiles[gateway]}), issuer:fixed(p.issuer_limits), client:fixed(p.client_profiles[client]),
    control_message_max_bytes:c(p.control_message_max_bytes), provision_batch_max:c(p.provision_batch_max)})
}))));

const counters = obj(Object.fromEntries([
  'verification_attempts','claims_successful','replays_rejected','requests_rejected','queue_rejected','transport_failures',
  'protected_requests_received','generation_mismatches','resources_served','issuance_successes','issuance_failures','observations'
].map(k=>[k,int()])), []);
const number = { type:'number', minimum:0, maximum:Number.MAX_SAFE_INTEGER };
const measurement = obj({ metric:choice(p.metrics), count:int(), failures:int(), elapsed_ms:number,
  p50_ms:either(number,nil),p95_ms:either(number,nil),p99_ms:either(number,nil),
  histogram_counts:arr(int(),p.histogram_bounds_ms.length+1,p.histogram_bounds_ms.length+1) });
const scenario = obj({scenario_id:choice(p.scenario_ids),status:choice(['PASS','FAIL','INCONCLUSIVE']),
  expected:choice(['accepted','rejected','single-spend','fail-closed','recovered','bearer-limit','bounded','measured','isolated','retention','observed-clock-regression']),
  counters,origin_counts_available:bool,
  worker_verification_attempts:arr(obj({worker_index:int(1),attempts:int()}),2),
  failure_labels:arr(choice([...Object.keys(p.gateway_results),...p.faults,'missing-evidence','assertion-failed','overload','transport-failure']),32)
});
const roleReport = obj({counters, measurements:arr(measurement,16),same_source_observed:either(bool,nil),origin_counts_available:bool,
  worker_verification_attempts:arr(obj({worker_index:int(1),attempts:int()}),2)});
const batchBase={batch_id:hex(32),batch_index:int(65535),expected_total:int(16384),final_batch:bool};
const refPath=str(128,'^/run/secrets/[A-Za-z0-9_.-]+$');
const roleConfig=obj({client_id:choice(['A','B','C','D','E']),tls_cert_path:refPath,tls_key_path:refPath,ca_cert_path:refPath,redis_credential_path:refPath},[]);
const requestCase = (command,payload,nullable=false,preparing=false) => obj({
  version:c(1),request_id:hex(32),command:c(command),
  run_id:nullable?either(hex(32),nil):hex(32),config_digest:preparing?nil:nullable?either(hex(64),nil):hex(64),
  target_incarnation:nullable?either(hex(32),nil):hex(32),payload
});
const requests = either(
  requestCase('STATUS',obj({}),true), requestCase('FENCE',obj({reason:choice(p.faults)}),true),
  requestCase('CREATE_ISSUER_KEY',obj({}),false,true),
  requestCase('PREPARE_RUN',obj({manifest,proposed_config_digest:hex(64),role:choice(['issuer','gateway','origin','client']),role_config:roleConfig}),false,true),
  requestCase('PROVISION_VOUCHERS',obj({...batchBase,items:arr(hex(64),128)})),
  requestCase('PROVISION_CLIENT',obj({...batchBase,items:arr(str(43,'^[A-Za-z0-9_-]{43}$'),128)})),
  ...['CHECK_READY','ENABLE','REPORT'].map(cmd=>requestCase(cmd,obj({}))),
  requestCase('HEARTBEAT',obj({seq:int(Number.MAX_SAFE_INTEGER,1)})),
  requestCase('RUN_SCENARIO',obj({scenario_id:choice(p.scenario_ids),schedule_seed:int(4294967295)}))
);
const errorResults=['BAD_VERSION','BAD_MESSAGE','WRONG_RUN','WRONG_CONFIG','WRONG_INCARNATION','ILLEGAL_STATE','DEPENDENCY_UNAVAILABLE','FAULTED'];
const responseBase={version:c(1),request_id:hex(32),state:choice(p.states),run_id:either(hex(32),nil),config_digest:either(hex(64),nil),incarnation:hex(32)};
const results={
  KEY_CREATED:obj({token_key_spki_b64url:publicKey,token_key_id:hex(64)}),PREPARED:obj({}),
  PROVISIONED:obj({received_total:int(16384),sealed:bool}),READY:obj({workers_ready:int(2)}),
  ENABLED:obj({workers_enabled:int(2)}),HEARTBEAT_ACK:obj({seq:int(Number.MAX_SAFE_INTEGER,1)}),FENCED:obj({}),
  STATUS:obj({ready:bool,run_closed:bool,fault:either(choice(p.faults),nil)}),REPORT:roleReport,SCENARIO_COMPLETE:scenario
};
const replies=either(...Object.entries(results).map(([result,data])=>obj({...responseBase,ok:c(true),result:c(result),data})),
  obj({...responseBase,ok:c(false),result:choice(errorResults),data:obj({})}));
const report=obj({schema_version:c(1),contract_version:c(p.contract_version),suite_kind:choice(['demo','security','benchmark']),suite_id:hex(32),
  created_at_utc:str(20,'^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$'),
  software:obj({git_commit:hex(40),dirty:bool,node_version:str(40),dependencies:obj({privacypass:c('0.9.0'),blindrsa:c('0.4.5')}),
    image_digests:arr(str(128,'^sha256:[0-9a-f]{64}$'),16)}),
  environment:obj({os:str(128),cpu_model:str(256),cpu_count:int(1024,1),memory_limit_bytes:int(),docker_version:str(64),topology:c('single-host-private')}),
  runs:arr(obj({run_id:hex(32),config_digest:hex(64),token_key_id:hex(64),gateway_profile:choice(['B0','B1']),client_profile:choice(['demo','security','benchmark']),
    origin_incarnation:either(hex(32),nil),scenario_results:arr(scenario,128),measurements:arr(measurement,16),
    state_transitions:arr(obj({state:choice(p.states),reason:either(choice(p.faults),c('startup'),c('ready'),c('enabled'),c('completed'))}),256),
    retention_checks:arr(obj({check_id:choice(['app-sinks','proxy-sinks','redis-diagnostics','mounts','runtime-files','report-allowlist','host-boundary']),status:choice(['PASS','FAIL','INCONCLUSIVE'])}),32)
  }),128),overall_status:choice(['PASS','FAIL','INCONCLUSIVE'])});
const schemas={'run-manifest-v1.json':manifest,'control-request-v1.json':requests,'control-response-v1.json':replies,'report-v1.schema.json':report,'scenario-result-v1.json':scenario};
mkdirSync(root+'src/contracts/schemas',{recursive:true});
for (const [name,schema] of Object.entries(schemas)) {
  const text=JSON.stringify({$schema:'http://json-schema.org/draft-07/schema#',$id:'https://tokenforge.invalid/contracts/'+name,...schema},null,2)+'\n';
  const path=root+'src/contracts/schemas/'+name;
  if(process.argv.includes('--check')) {if(readFileSync(path,'utf8')!==text)throw Error('Schema drift: '+name);}
  else writeFileSync(path,text);
}
console.log(process.argv.includes('--check')?'Contract schemas match generator':'Generated strict contract schemas');
