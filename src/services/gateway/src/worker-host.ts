import { prepareRegionalGateway } from './regional-gateway.ts';
import { validateRegionalStartup, type RegionalStartup } from './regional-startup.ts';
import type { RegionalCoordinator } from './regional-coordinator.ts';
import type { RegionalReplayStore } from './regional-replay-store.ts';
import { ResourceProbe } from '../../../contracts/lib/resources.ts';
import { SourceObservation } from './source-observation.ts';
import { ContractError, validateManifest, type Manifest } from '../../../contracts/lib/index.ts';
import { WorkerLease, type WorkerCloseReason, type WorkerLeaseGrant } from './worker-lease.ts';
import { openRedisReplayStore, type RedisEndpoint } from './redis-adapter.ts';
import type { ReplayStore } from './replay-store.ts';
import { FixedOrigin } from './fixed-origin.ts';
import { RequestCoordinator } from './request-coordinator.ts';
import { HttpsGateway, type GatewayTls } from './https-gateway.ts';

/** One immutable run in one serving process. No retry, replacement pool or same-run recovery. */
export class WorkerHost {
  readonly lease: WorkerLease;
  readonly #resources = new ResourceProbe('gateway-worker');
  get resources() { return [this.#resources.summary()]; }
  get rpcOutcomes() { return this.#store&&'rpcOutcomes' in this.#store?this.#store.rpcOutcomes:[]; }
  readonly #manifest: Manifest;
  #store: ReplayStore | RegionalReplayStore | null = null;
  #origin: FixedOrigin | null = null;
  #coordinator: RequestCoordinator | RegionalCoordinator | null = null;
  #https: HttpsGateway | null = null;
  #preparation: Promise<void> = Promise.resolve();
  #drain: Promise<void> | null = null;
  #closed = false;
  #source: SourceObservation | undefined;
  get source() { return this.#source?.summary() ?? { observations: 0, consistent: null, tag: null }; }

  private constructor(m: Manifest, worker: string, supervisor: string, onFault: (reason: WorkerCloseReason) => void) {
    this.#manifest = m;
    this.lease = WorkerLease.prepare(m, { worker_incarnation: worker, supervisor_incarnation: supervisor }, reason => {
      if (reason !== 'operator-stop' && reason !== 'test-cleanup') onFault(reason);
      void this.close();
    });
  }
  static prepare(manifest: unknown, worker: string, supervisor: string, endpoint: RedisEndpoint, tls: GatewayTls,
    onFault: (reason: WorkerCloseReason) => void, sourceKey?: string, regional?: RegionalStartup): WorkerHost {
    const host = new WorkerHost(validateManifest(structuredClone(manifest)), worker, supervisor, onFault);
    if (sourceKey) host.#source = new SourceObservation(sourceKey);
    host.#preparation = host.#prepare({...endpoint}, {...tls}, regional?validateRegionalStartup(regional):undefined);
    host.#preparation.catch(() => { host.lease.requestClose('dependency-lost'); });
    return host;
  }
  async #prepare(endpoint: RedisEndpoint, tls: GatewayTls, regional?:RegionalStartup): Promise<void> {
    if(regional){
      const a=regional.auth,keys:Buffer[]=[];
      const key=(text:string)=>{const bytes=Buffer.from(text,'hex');keys.push(bytes);return bytes;};
      try{
        const auth=a.profile==='arc'?{...a,verify_key:key(a.verify_key)}:a.profile==='type2-holder'?{...a,context_key:key(a.context_key),nonce_key:key(a.nonce_key)}:
          a.profile==='ip'?{...a,source_key:key(a.source_key)}:a;
        const prepared=await prepareRegionalGateway(this.#manifest,regional.policy,this.lease,{redis:endpoint,tls,auth,...(this.#source?{source:this.#source}:{})});
        this.#store=prepared.replay;this.#coordinator=prepared.coordinator;this.#https=prepared.gateway;
        if(this.#closed)throw new ContractError('worker-closed');
        return;
      }finally{keys.forEach(bytes=>bytes.fill(0));}
    }
    this.#store = await openRedisReplayStore(this.#manifest, endpoint, reason => this.lease.requestClose(reason));
    if (this.#closed) throw new ContractError('worker-closed');
    this.#origin = FixedOrigin.prepare(this.#manifest, this.lease);
    this.#coordinator = await RequestCoordinator.prepare(this.#manifest, this.lease, this.#store, this.#origin);
    if (this.#closed) throw new ContractError('worker-closed');
    this.#https = HttpsGateway.prepare(this.#manifest, this.lease, this.#coordinator, tls, undefined, this.#source);
  }
  async ready(): Promise<void> {
    await this.#preparation;
    if (this.#closed || this.lease.status.state !== 'READY') throw new ContractError('worker-not-ready');
  }
  enable(grant: WorkerLeaseGrant): boolean { return !this.#closed && !!this.#https && this.lease.enable(grant); }
  heartbeat(grant: WorkerLeaseGrant): boolean { return !this.#closed && this.lease.heartbeat(grant); }
  async listen(host: string, port: number): Promise<void> {
    if (this.#closed || !this.#https || !this.lease.checkActive()) throw new ContractError('worker-not-enabled');
    await this.#https.listen(host, port);
    if (!this.lease.checkActive() || this.#closed) throw new ContractError('worker-not-enabled');
  }
  get counters(){return this.#coordinator&&'counters' in this.#coordinator?this.#coordinator.counters:undefined;}
  get measurements() { return [...(this.#coordinator?.measurements ?? []), ...(this.#store&&'measurements' in this.#store?this.#store.measurements:[])]; }
  get attempts(): number { return this.#coordinator?.verificationAttempts ?? 0; }
  close(): Promise<void> {
    if (this.#drain) return this.#drain;
    let resolve!: () => void, reject!: (error: Error) => void;
    this.#drain = new Promise<void>((done, failed) => { resolve = done; reject = failed; });
    this.#drain.catch(() => {}); this.#closed = true; this.lease.fence();
    // Preparation may still be importing the public key or connecting Redis. Drain it before acknowledgement.
    this.#preparation.catch(() => {}).then(async () => {
      const results = await Promise.allSettled([
        this.#https?.close(), this.#coordinator?.close(), this.#origin?.close(),
      ]);
      this.#store?.close();
      if (results.some(result => result.status === 'rejected')) throw new Error();
    }).then(resolve, () => reject(new ContractError('worker-close-failed')));
    return this.#drain;
  }
}
