/** Pure aggregate analysis. Call after schema validation; no request records or correlation identifiers. */
export function analyzeBenchmark(runs: readonly unknown[]) {
  type Row = { gateway_profile: string; experiment?: {condition:number;stage:string;repetition:number}|null;
    scenario_results: {scenario_id:string;status:string;counters:Record<string,number>}[];
    measurements:{metric:string;count:number;elapsed_ms:number}[];rpc_outcomes?:{failures:number}[] };
  const rows = runs as readonly Row[];
  const median = (xs: number[]) => { const a=[...xs].sort((a,b)=>a-b);return a.length ? a.length%2 ? a[Math.floor(a.length/2)]! : (a[a.length/2-1]!+a[a.length/2]!)/2 : null; };
  const conditions = [1,10,50].map(condition => {
    const matching=rows.filter(r=>r.experiment?.condition===condition);
    const trials=matching.filter(r=>r.experiment?.stage==='measured');
    const valid=(r:Row) => {
      const s=r.scenario_results.find(s=>s.scenario_id==='performance'), c=s?.counters;
      const m=r.measurements.find(m=>m.metric==='protected_response_ms');
      return s?.status==='PASS' && !!c && c['claims_successful']!>=1000 && c['uncertain_operations']===0 && c['timed_out_operations']===0
        && c['not_started_operations']===0 && (c['issuance_failures']??0)===0 && c['requests_rejected']===0
        && c['protected_requests_received']===c['claims_successful'] && c['resources_served']===c['claims_successful'] && c['generation_mismatches']===0
        && c['attempted_operations']===c['completed_operations'] && c['completed_operations']===c['claims_successful']!+(c['queue_rejected']??0)
        && !!m && m.count===c['claims_successful'] && m.elapsed_ms>0 && r.rpc_outcomes?.length===2 && r.rpc_outcomes.every(r=>r.failures===0);
    };
    const profiles=['B0','B1'].map(profile=>{
      const rs=trials.filter(r=>r.gateway_profile===profile);
      const rates=rs.filter(valid).map(r=>{const m=r.measurements.find(m=>m.metric==='protected_response_ms')!;return m.count/m.elapsed_ms*1000;});
      const mean=rates.length?rates.reduce((a,b)=>a+b,0)/rates.length:0;
      const cv=mean>0?Math.sqrt(rates.reduce((a,b)=>a+(b-mean)**2,0)/rates.length)/mean:null;
      return {profile,trials:rs.length,valid_trials:rates.length,median_successes_per_second:median(rates),coefficient_of_variation:cv,
        rejected:rs.reduce((n,r)=>n+r.scenario_results.reduce((a,s)=>a+(s.counters['queue_rejected']??0)+(s.counters['requests_rejected']??0),0),0)};
    });
    const warmup= ['B0','B1'].every(p=>matching.some(r=>r.experiment?.stage==='warmup'&&r.gateway_profile===p&&r.scenario_results.every(s=>s.status==='PASS')));
    const order=trials.map(r=>r.gateway_profile).join(',')==='B0,B1,B1,B0,B0,B1';
    const repetitions=profiles.every(p=>[1,2,3].every(n=>trials.filter(r=>r.gateway_profile===p.profile&&r.experiment?.repetition===n).length===1));
    const comparable=warmup&&order&&repetitions&&profiles.every(p=>p.valid_trials===3);
    return {condition,warmup_complete:warmup,alternating_order:order,comparable,profiles,gain:comparable?profiles[1]!.median_successes_per_second!/profiles[0]!.median_successes_per_second!-1:null};
  });
  return {complete:conditions.every(c=>c.comparable),conditions};
}
