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
  readonly #manifest: Manifest;
  #store: ReplayStore | null = null;
  #origin: FixedOrigin | null = null;
  #coordinator: RequestCoordinator | null = null;
  #https: HttpsGateway | null = null;
  #preparation: Promise<void> = Promise.resolve();
  #drain: Promise<void> | null = null;
  #closed = false;

  private constructor(m: Manifest, worker: string, supervisor: string, onFault: (reason: WorkerCloseReason) => void) {
    this.#manifest = m;
    this.lease = WorkerLease.prepare(m, { worker_incarnation: worker, supervisor_incarnation: supervisor }, reason => {
      if (reason !== 'operator-stop' && reason !== 'test-cleanup') onFault(reason);
      void this.close();
    });
  }
  static prepare(manifest: unknown, worker: string, supervisor: string, endpoint: RedisEndpoint, tls: GatewayTls,
    onFault: (reason: WorkerCloseReason) => void): WorkerHost {
    const host = new WorkerHost(validateManifest(structuredClone(manifest)), worker, supervisor, onFault);
    host.#preparation = host.#prepare(endpoint, tls);
    host.#preparation.catch(() => { host.lease.requestClose('dependency-lost'); });
    return host;
  }
  async #prepare(endpoint: RedisEndpoint, tls: GatewayTls): Promise<void> {
    this.#store = await openRedisReplayStore(this.#manifest, endpoint, reason => this.lease.requestClose(reason));
    if (this.#closed) throw new ContractError('worker-closed');
    this.#origin = FixedOrigin.prepare(this.#manifest, this.lease);
    this.#coordinator = await RequestCoordinator.prepare(this.#manifest, this.lease, this.#store, this.#origin);
    if (this.#closed) throw new ContractError('worker-closed');
    this.#https = HttpsGateway.prepare(this.#manifest, this.lease, this.#coordinator, tls);
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
