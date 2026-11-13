// Bounded S18 mint/redemption phases. Fixed settings and timer boundaries: docs/lab/BENCHMARK.md.
// Tokens stay in the existing bounded in-memory inventory; only aggregate REPORT data leaves the client.
import { performance } from 'node:perf_hooks';
import type { ScenarioContext, ScenarioOutcome } from './control.ts';
import { LabClientError } from './client.ts';
import { Histogram } from '../report/histogram.ts';

// The controller serializes preparation across clients. Yield between operations without
// an artificial signing delay so the bounded inventory can be prepared within its epoch.
export const TOKENS = 80, WORKERS = 3, MINT_PACE_MS = 0;
export const EXPERIMENT_SETTINGS = {
  1:{ tokens:400,workers:1,stage:'measured' }, 10:{tokens:80,workers:2,stage:'measured'},50:{tokens:200,workers:10,stage:'measured'},
  101:{tokens:100,workers:1,stage:'warmup'},110:{tokens:20,workers:2,stage:'warmup'},150:{tokens:20,workers:10,stage:'warmup'},
} as const;
export type PerfDeps = { sleep: (ms: number) => Promise<void>; now: () => number };
const real: PerfDeps = { sleep: (ms) => new Promise((r) => setTimeout(r, ms)), now: () => performance.now() };

/** Challenge requests carry no token. Only a confirmed busy refusal permits another attempt. */
export async function benchmarkChallenge(ctx: Pick<ScenarioContext, 'client' | 'signal'>, sleep: PerfDeps['sleep']) {
  for (let attempt = 0; attempt < 3; attempt++) {
    if (ctx.signal.aborted) throw new LabClientError('client-closed');
    try { return await ctx.client.fetchChallenge(); }
    catch (error) {
      if (!(error instanceof LabClientError) || error.status !== 503 || error.label !== 'gateway-busy' || attempt === 2) throw error;
      await sleep(250);
    }
  }
  throw new LabClientError('challenge-unavailable');
}

export async function performanceWith(ctx: ScenarioContext, d: PerfDeps = real): Promise<ScenarioOutcome> {
  const { client, signal } = ctx;
  const phase = ctx.seed === undefined ? 'full' : ctx.seed >= 10000 ? 'mint' : 'redeem';
  const seed = ctx.seed === undefined ? undefined : ctx.seed % 10000;
  const setting = seed === undefined ? {tokens:TOKENS,workers:WORKERS,stage:'test'} : EXPERIMENT_SETTINGS[seed as keyof typeof EXPERIMENT_SETTINGS];
  if (!setting || (ctx.seed !== undefined && ctx.seed !== seed && ctx.seed !== 10000 + seed!)) return {status:'INCONCLUSIVE',expected:'measured',failure_labels:['missing-evidence']};
  const {tokens,workers} = setting;
  if (phase !== 'redeem' && !ctx.hasVoucher(tokens)) return { status:'INCONCLUSIVE',expected:'measured',failure_labels:['missing-evidence'] };
  let parsed;
  try { parsed = await benchmarkChallenge(ctx, d.sleep); }
  catch (error) {
    const busy = error instanceof LabClientError && error.status === 503 && error.label === 'gateway-busy';
    return { status: busy || signal.aborted ? 'INCONCLUSIVE' : 'FAIL', expected: 'measured',
      counters: { attempted_operations: 0, completed_operations: 0, not_started_operations: tokens },
      failure_labels: [busy || signal.aborted ? 'missing-evidence' : 'authorization-unavailable'] };
  }
  const acquisition = new Histogram(), response = new Histogram(), http = new Histogram();
  const wires: Uint8Array[] = [];
  let mintElapsed = 0, mintFailures = 0;
  try {
    if (phase !== 'redeem') {
      const mintStart = d.now();
      for (let i=0;i<tokens && !signal.aborted;i++) {
        const t=d.now();
        try { const wire=await client.issueWire(parsed.challenge,(ms,ok)=>{if(ok)http.add(ms);else http.fail();}); wires.push(wire); acquisition.add(d.now()-t); }
        catch {mintFailures++;acquisition.fail();}
        await d.sleep(MINT_PACE_MS);
      }
      mintElapsed=d.now()-mintStart;
      if(phase==='mint') {
        for(const wire of wires) client.tokens.add(parsed.epoch,wire);
        return {status:wires.length===tokens && !signal.aborted?'PASS':'FAIL',expected:'measured',
          counters:{issuance_successes:wires.length,issuance_failures:mintFailures},
          failure_labels:wires.length===tokens?[]:['assertion-failed'],
          measurements:[http.summary('issuance_http_ms',mintElapsed),acquisition.summary('token_acquisition_ms',mintElapsed)]};
      }
    } else {
      for(let i=0;i<tokens;i++) {const wire=client.tokens.take(parsed.epoch);if(!wire)break;wires.push(wire);}
    }
    let next=0,ok=0,busy=0,other=0,lost=0,timedOut=0,attempted=0;
    const redeemStart=d.now();
    await Promise.all(Array.from({length:workers},async()=>{
      for(;;) {
        const i=next++;if(i>=wires.length||signal.aborted)return;
        attempted++;const t=d.now();
        const r=await client.redeemWire(wires[i]!).catch(error=>{if(error instanceof LabClientError&&error.timedOut)timedOut++;return null;});
        if(r===null){lost++;response.fail();}
        else if(r.status===200){ok++;response.add(d.now()-t);}
        else if(r.status===503&&r.label==='gateway-busy'){busy++;response.fail();}
        else{other++;response.fail();}
      }
    }));
    const redeemElapsed=d.now()-redeemStart;
    const endEpoch=await benchmarkChallenge(ctx, d.sleep).then(r=>r.epoch).catch(()=>null);
    const clean=other===0&&lost===0&&mintFailures===0&&attempted===tokens&&endEpoch===parsed.epoch&&!signal.aborted;
    return {status:clean?'PASS':endEpoch===null?'INCONCLUSIVE':'FAIL',expected:'measured',
      counters:{attempted_operations:attempted,completed_operations:ok+busy+other,timed_out_operations:timedOut,uncertain_operations:lost,not_started_operations:tokens-attempted,
        observations:wires.length,...(phase==='full'?{issuance_successes:wires.length,issuance_failures:mintFailures}:{}),claims_successful:ok,queue_rejected:busy,transport_failures:lost,requests_rejected:other},
      failure_labels:clean?[]:endEpoch===null?['missing-evidence']:endEpoch!==parsed.epoch?['token-expired']:['assertion-failed'],
      measurements:[...(phase==='full'?[http.summary('issuance_http_ms',mintElapsed),acquisition.summary('token_acquisition_ms',mintElapsed)]:[]),response.summary('protected_response_ms',redeemElapsed)]};
  } finally {for(const w of wires)w.fill(0);}
}
export const performance_ = (ctx: ScenarioContext): Promise<ScenarioOutcome> => performanceWith(ctx);
