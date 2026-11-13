// S18 performance (client part). The same declared load runs against the B0 and the B1 gateway, with identical security
// semantics, and only aggregates leave this file: two fixed-bucket histograms (token acquisition and protected response) with
// counts, failures and elapsed time. Method:
//   * Every client first mints TOKENS tokens, paced (a burst of minting from five clients would starve the issuer's control
//     heartbeat, and the supervision deadline is never lengthened). Minting is timed as `token_acquisition_ms`
//     (blinding + issuer POST + finalization + public verification, for one token).
//   * Then each client presents its tokens once each, with WORKERS requests in flight, as one closed loop. The latency of a
//     request is `protected_response_ms` (client side: request start to complete response). A 503 `gateway-busy` is counted as a
//     failure and is NOT retried, so the number is the declared load's honest result. Total in flight is clients x WORKERS = 15,
//     which fits the one-worker B0 gateway (1 active flow + 16 queued) so both profiles face the same load.
// The clients and the gateway share one host and the CPU is shared with the issuer's signing, so absolute numbers describe this
// lab, not a deployment. The gateway closes every response connection: CONNECT and TLS setup are paid per redemption.
import { performance } from 'node:perf_hooks';
import type { ScenarioContext, ScenarioOutcome } from './control.ts';
import { LabClientError } from './client.ts';
import { Histogram } from '../report/histogram.ts';

export const TOKENS = 80, WORKERS = 3, MINT_PACE_MS = 200;
export const EXPERIMENT_SETTINGS = {
  1:{ tokens:1000,workers:1,stage:'measured' }, 10:{tokens:200,workers:2,stage:'measured'},50:{tokens:400,workers:10,stage:'measured'},
  101:{tokens:100,workers:1,stage:'warmup'},110:{tokens:20,workers:2,stage:'warmup'},150:{tokens:20,workers:10,stage:'warmup'},
} as const;
export type PerfDeps = { sleep: (ms: number) => Promise<void>; now: () => number };
const real: PerfDeps = { sleep: (ms) => new Promise((r) => setTimeout(r, ms)), now: () => performance.now() };

export async function performanceWith(ctx: ScenarioContext, d: PerfDeps = real): Promise<ScenarioOutcome> {
  const { client, signal } = ctx;
  const phase = ctx.seed === undefined ? 'full' : ctx.seed >= 10000 ? 'mint' : 'redeem';
  const seed = ctx.seed === undefined ? undefined : ctx.seed % 10000;
  const setting = seed === undefined ? {tokens:TOKENS,workers:WORKERS,stage:'test'} : EXPERIMENT_SETTINGS[seed as keyof typeof EXPERIMENT_SETTINGS];
  if (!setting) return {status:'INCONCLUSIVE',expected:'measured',failure_labels:['missing-evidence']};
  const {tokens,workers} = setting;
  if (phase !== 'redeem' && !ctx.hasVoucher(tokens)) return { status:'INCONCLUSIVE',expected:'measured',failure_labels:['missing-evidence'] };
  const parsed = await client.fetchChallenge();
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
    const endEpoch=await client.fetchChallenge().then(r=>r.epoch).catch(()=>null);
    const clean=other===0&&lost===0&&mintFailures===0&&attempted===tokens&&endEpoch===parsed.epoch&&!signal.aborted;
    return {status:clean?'PASS':'FAIL',expected:'measured',
      counters:{attempted_operations:attempted,completed_operations:ok+busy+other,timed_out_operations:timedOut,uncertain_operations:lost,not_started_operations:tokens-attempted,
        observations:wires.length,...(phase==='full'?{issuance_successes:wires.length,issuance_failures:mintFailures}:{}),claims_successful:ok,queue_rejected:busy,transport_failures:lost,requests_rejected:other},
      failure_labels:clean?[]:endEpoch!==parsed.epoch?['token-expired']:['assertion-failed'],
      measurements:[...(phase==='full'?[http.summary('issuance_http_ms',mintElapsed),acquisition.summary('token_acquisition_ms',mintElapsed)]:[]),response.summary('protected_response_ms',redeemElapsed)]};
  } finally {for(const w of wires)w.fill(0);}
}
export const performance_ = (ctx: ScenarioContext): Promise<ScenarioOutcome> => performanceWith(ctx);
