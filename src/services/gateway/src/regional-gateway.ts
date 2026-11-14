import { ContractError, validateManifest } from '../../../contracts/lib/index.ts';
import { validateRegionalPolicy } from '../../../contracts/lib/regional.ts';
import { ArcVerifierClient } from './arc-verifier-client.ts';
import { HolderVerifier } from './holder-verifier.ts';
import { openRegionalRedisReplayStore, type RedisEndpoint } from './redis-adapter.ts';
import { FixedOrigin } from './fixed-origin.ts';
import { HttpsGateway, type GatewayTls } from './https-gateway.ts';
import { RegionalCoordinator, type RegionalProofVerifier } from './regional-coordinator.ts';
import type { RegionalReplayStore } from './regional-replay-store.ts';
import type { WorkerLease } from './worker-lease.ts';

export type RegionalGatewayOptions={redis:RedisEndpoint;tls:GatewayTls;auth:
  {profile:'arc';bootstrap:unknown;endpoint:{host:string;port:number};verify_key:Uint8Array}|
  {profile:'type2-holder';context_key:Uint8Array;nonce_key:Uint8Array}};

/** Explicit prepared factory, not a second controller. It never enables a lease or publishes a listener. */
export async function prepareRegionalGateway(configuration:unknown,policy:unknown,lease:WorkerLease,options:RegionalGatewayOptions){
  const m=validateManifest(structuredClone(configuration)),p=validateRegionalPolicy(policy,m);
  let verifier:RegionalProofVerifier|undefined,replay:RegionalReplayStore|undefined,origin:FixedOrigin|undefined,coordinator:RegionalCoordinator|undefined;
  try{
    if(!options||options.auth.profile!==p.profile||lease.status.state!=='PREPARED')throw Error();
    // Capture all startup values, including keys and endpoint, before awaiting external I/O.
    const tls={key:options.tls.key,cert:options.tls.cert},endpoint={...options.redis};
    if(options.auth.profile==='arc')verifier=ArcVerifierClient.prepare(p,options.auth.bootstrap,{...options.auth.endpoint},
      options.auth.verify_key,m.limits.gateway.active_flows_per_worker as 1|2,()=>{lease.requestClose('dependency-lost');});
    else verifier=await HolderVerifier.prepare(m,p,options.auth.context_key,options.auth.nonce_key);
    replay=await openRegionalRedisReplayStore(m,p,endpoint,reason=>{lease.requestClose(reason);});
    origin=FixedOrigin.prepare(m,lease);coordinator=RegionalCoordinator.prepare(m,p,lease,replay,origin,verifier);
    const gateway=HttpsGateway.prepare(m,lease,coordinator,tls);
    return Object.freeze({gateway,coordinator});
  }catch{
    lease.requestClose('unsafe-state');
    if(coordinator)await coordinator.close().catch(()=>{});
    else{replay?.close();await Promise.allSettled([verifier?.close(),origin?.close()]);}
    throw new ContractError('regional-gateway-preparation');
  }
}
