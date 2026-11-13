import protocol from '../protocol-v1.json' with {type:'json'};
/** Pure aggregate analysis after schema validation. No request histories or correlation timelines. */
export function analyzeBenchmark(runs: readonly unknown[]) {
  type Row = {run_id:string;token_key_id:string;reset_confirmed?:boolean|null;client_profile:string;gateway_profile:string;
    experiment?:{condition:number;stage:string;repetition:number}|null;
    resources?:{scope:string;worker_index:number|null;elapsed_ms:number;peak_rss_bytes:number;cpu_user_us:number;cpu_system_us:number}[];
    scenario_results:{scenario_id:string;status:string;origin_counts_available:boolean;counters:Record<string,number>;worker_verification_attempts:{worker_index:number;attempts:number}[]}[];
    measurements:{metric:string;count:number;failures:number;elapsed_ms:number}[];
    rpc_outcomes?:{operation:string;failures:number;timeouts:number;uncertain:number}[]};
  const rows=runs as readonly Row[];
  const independent=rows.every(r=>typeof r.run_id==='string'&&typeof r.token_key_id==='string')
    &&new Set(rows.map(r=>r.run_id)).size===rows.length&&new Set(rows.map(r=>r.token_key_id)).size===rows.length;
  const median=(xs:number[])=>{const a=[...xs].sort((a,b)=>a-b);return a.length?a.length%2?a[Math.floor(a.length/2)]!:(a[a.length/2-1]!+a[a.length/2]!)/2:null;};
  const conditions=[1,10,50].map(condition=>{
    const matching=rows.filter(r=>r.experiment?.condition===condition),trials=matching.filter(r=>r.experiment?.stage==='measured');
    const valid=(r:Row,attempts:number)=>{
      const s=r.scenario_results.length===1?r.scenario_results[0]:undefined,c=s?.counters;
      if(!s||s.scenario_id!=='performance'||s.status!=='PASS'||!s.origin_counts_available||!c||r.reset_confirmed!==true||r.client_profile!=='benchmark')return false;
      const metric=(name:string)=>r.measurements.find(m=>m.metric===name)!;
      if(r.measurements.length!==8||protocol.metrics.some(name=>r.measurements.filter(m=>m.metric===name).length!==1))return false;
      const successes=c['claims_successful']??0;
      if(successes<=0||c['attempted_operations']!==attempts||c['completed_operations']!==attempts||c['uncertain_operations']!==0||c['timed_out_operations']!==0||c['not_started_operations']!==0||c['issuance_failures']!==0||c['requests_rejected']!==0)return false;
      if(c['completed_operations']!==successes+(c['queue_rejected']??0)||c['protected_requests_received']!==successes||c['resources_served']!==successes||c['generation_mismatches']!==0)return false;
      if(c['issuance_successes']!==attempts||['issuance_http_ms','token_acquisition_ms'].some(n=>metric(n).count!==attempts||metric(n).failures!==0))return false;
      if(metric('protected_response_ms').count!==successes||metric('protected_response_ms').failures!==(c['queue_rejected']??0)||metric('protected_response_ms').elapsed_ms<=0)return false;
      if(['verification_ms','authorization_ms','claim_rpc_ms'].some(n=>metric(n).count<successes)||metric('snapshot_rpc_ms').count<metric('claim_rpc_ms').count)return false;
      const rpc=r.rpc_outcomes;
      if(rpc?.length!==2||['snapshot','claim'].some(op=>rpc.filter(o=>o.operation===op).length!==1)||rpc.some(o=>o.failures!==0||o.timeouts!==0||o.uncertain!==0))return false;
      const workers=r.gateway_profile==='B0'?1:2,attemptRows=s.worker_verification_attempts;
      if(attemptRows.length!==workers||Array.from({length:workers},(_,i)=>i).some(i=>attemptRows.filter(a=>a.worker_index===i&&a.attempts>0).length!==1))return false;
      const resources=r.resources;
      if(!resources||resources.some(r=>r.elapsed_ms<=0||r.peak_rss_bytes<=0||r.cpu_user_us<0||r.cpu_system_us<0))return false;
      if(['gateway-supervisor','controller','issuer','origin'].some(scope=>resources.filter(r=>r.scope===scope&&r.worker_index===null).length!==1))return false;
      if(resources.filter(r=>r.scope==='client'&&r.worker_index===null).length!==(condition===1?1:5))return false;
      const wr=resources.filter(r=>r.scope==='gateway-worker');
      return wr.length===workers&&Array.from({length:workers},(_,i)=>i).every(i=>wr.filter(r=>r.worker_index===i).length===1);
    };
    const attempts=condition===50?1000:400;
    const profiles=['B0','B1'].map(profile=>{
      const rs=trials.filter(r=>r.gateway_profile===profile),good=rs.filter(r=>valid(r,attempts));
      const rates=good.map(r=>{const m=r.measurements.find(m=>m.metric==='protected_response_ms')!;return m.count/m.elapsed_ms*1000;});
      const mean=rates.length?rates.reduce((a,b)=>a+b,0)/rates.length:0;
      return {profile,trials:rs.length,valid_trials:good.length,successful_operations:good.reduce((n,r)=>n+(r.scenario_results[0]!.counters['claims_successful']??0),0),median_successes_per_second:median(rates),
        coefficient_of_variation:mean>0?Math.sqrt(rates.reduce((n,x)=>n+(x-mean)**2,0)/rates.length)/mean:null,
        rejected:rs.reduce((n,r)=>n+r.scenario_results.reduce((n,s)=>n+(s.counters['queue_rejected']??0)+(s.counters['requests_rejected']??0),0),0)};
    });
    const warmups=matching.filter(r=>r.experiment?.stage==='warmup');
    const warmup=warmups.length===2&&['B0','B1'].every(p=>warmups.filter(r=>r.gateway_profile===p&&r.experiment?.repetition===1&&valid(r,100)).length===1)
      &&matching.slice(0,2).every(r=>r.experiment?.stage==='warmup');
    const expected=[['B0',1],['B1',1],['B1',2],['B0',2],['B0',3],['B1',3]];
    const order=trials.length===6&&trials.every((r,i)=>r.gateway_profile===expected[i]![0]&&r.experiment?.repetition===expected[i]![1]);
    const comparable=independent&&warmup&&order&&profiles.every(p=>p.valid_trials===3&&p.successful_operations>=1000);
    return {condition,warmup_complete:warmup,alternating_order:order,comparable,profiles,gain:comparable?profiles[1]!.median_successes_per_second!/profiles[0]!.median_successes_per_second!-1:null};
  });
  return {complete:rows.length===24&&conditions.every(c=>c.comparable),conditions};
}
