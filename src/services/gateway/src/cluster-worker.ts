import cluster, { type Worker } from 'node:cluster';
import { randomBytes } from 'node:crypto';
import type { Manifest } from '../../../contracts/lib/index.ts';
import type { RedisEndpoint } from './redis-adapter.ts';
import type { GatewayTls } from './https-gateway.ts';
import type { WorkerCloseReason, WorkerLeaseGrant } from './worker-lease.ts';
import type { SupervisorWorker, WorkerFactory } from './gateway-supervisor.ts';

export type WorkerConfiguration = { endpoint: RedisEndpoint; tls: GatewayTls; listen_host: string; listen_port: number };
const reasons = new Set(['operator-stop', 'test-cleanup', 'unsafe-state', 'lease-expired', 'dependency-lost',
  'clock-unsafe', 'process-exited', 'control-lost', 'configuration-mismatch']);

class ClusterWorker implements SupervisorWorker {
  incarnation = '';
  readonly #worker: Worker;
  readonly #configuration: WorkerConfiguration;
  readonly #fault: (reason: WorkerCloseReason) => void;
  readonly #exit: Promise<void>;
  readonly #ready: Promise<void>;
  #pending: { id: string; resolve: (value: Record<string, unknown>) => void; reject: () => void; cancel: () => void } | null = null;
  #stopping = false;
  #drain: Promise<void> | null = null;

  constructor(configuration: WorkerConfiguration, fault: (reason: WorkerCloseReason) => void) {
    this.#configuration = configuration; this.#fault = fault;
    const before = process.hrtime.bigint(); this.#worker = cluster.fork();
    this.#worker.process.stdout?.resume(); this.#worker.process.stderr?.resume(); // Never publish child exception details.
    this.#exit = new Promise(resolve => this.#worker.once('exit', () => {
      this.#pending?.cancel(); this.#pending?.reject(); this.#pending = null;
      if (!this.#stopping) fault('process-exited'); resolve();
    }));
    this.#worker.on('error', () => { if (!this.#stopping) fault('dependency-lost'); });
    this.#worker.on('disconnect', () => { if (!this.#stopping) fault('control-lost'); });
    this.#ready = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(Error('worker-start-failed')), 3000);
      this.#worker.once('exit', () => { clearTimeout(timer); reject(Error('worker-start-failed')); });
      this.#worker.on('message', (raw: unknown) => {
        const m = raw as Record<string, unknown>;
        if (!m || typeof m !== 'object' || Array.isArray(m) || Buffer.byteLength(JSON.stringify(m)) > 1024) { fault('unsafe-state'); return; }
        if (m['kind'] === 'hello' && !this.incarnation) {
          const stamp = m['stamp'];
          if (Object.keys(m).length !== 3 || typeof m['incarnation'] !== 'string' || !/^[0-9a-f]{32}$/.test(m['incarnation']) ||
            typeof stamp !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(stamp) || BigInt(stamp) < before || BigInt(stamp) > process.hrtime.bigint()) { fault('clock-unsafe'); return; }
          this.incarnation = m['incarnation']; clearTimeout(timer); resolve(); return;
        }
        if (m['kind'] === 'fault' && Object.keys(m).length === 2 && reasons.has(m['reason'] as string)) { fault(m['reason'] as WorkerCloseReason); return; }
        const pending = this.#pending;
        if (m['kind'] !== 'reply' || !pending || m['id'] !== pending.id || m['ok'] !== true ||
          Object.keys(m).some(key => !['kind', 'id', 'ok', 'attempts'].includes(key))) { if (!this.#stopping) fault('unsafe-state'); return; }
        this.#pending = null; pending.cancel(); pending.resolve(m);
      });
    });
    this.#ready.catch(() => {});
  }
  async ready(): Promise<void> { try { await this.#ready; } catch { await this.close(); throw Error('worker-start-failed'); } }
  #call(command: string, payload: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    if (this.#stopping || this.#pending || !this.#worker.isConnected()) return Promise.reject(Error('worker-unavailable'));
    return new Promise((resolve, reject) => {
      const id = randomBytes(16).toString('hex');
      const failed = () => { if (this.#pending?.id === id) this.#pending = null; reject(Error('worker-operation-failed')); };
      const timer = setTimeout(() => { failed(); this.#fault('control-lost'); }, command === 'PREPARE' ? 5000 : 2000);
      this.#pending = { id, resolve, reject: failed, cancel: () => clearTimeout(timer) };
      try {
        if (!this.#worker.send({ id, command, ...payload }, error => { if (error) { clearTimeout(timer); failed(); this.#fault('control-lost'); } })) {
          clearTimeout(timer); failed(); this.#fault('control-lost');
        }
      } catch { clearTimeout(timer); failed(); this.#fault('control-lost'); }
    });
  }
  async prepare(manifest: Manifest, supervisor: string): Promise<void> { await this.#call('PREPARE', { manifest, supervisor, configuration: this.#configuration }); }
  async enable(grant: WorkerLeaseGrant): Promise<void> { await this.#call('ENABLE', { grant }); }
  async listen(): Promise<void> { await this.#call('LISTEN'); }
  async heartbeat(grant: WorkerLeaseGrant): Promise<void> { await this.#call('HEARTBEAT', { grant }); }
  async attempts(): Promise<number> { return (await this.#call('REPORT'))['attempts'] as number; }
  close(): Promise<void> {
    if (this.#drain) return this.#drain;
    let resolve!: () => void;
    this.#drain = new Promise(done => { resolve = done; }); this.#stopping = true;
    this.#pending?.cancel(); this.#pending?.reject(); this.#pending = null;
    // Graceful STOP has a hard fallback. Neither IPC disconnect nor a STOP reply proves exit.
    const timer = setTimeout(() => { this.#worker.process.kill('SIGKILL'); }, 1000);
    try { this.#worker.send({ id: randomBytes(16).toString('hex'), command: 'STOP' }, () => {}); }
    catch { this.#worker.process.kill('SIGKILL'); }
    this.#exit.then(() => { clearTimeout(timer); resolve(); }); return this.#drain;
  }
}

/** Configure once before any fork. SCHED_NONE avoids the primary's unbounded round-robin accepted-socket queue. */
export function clusterWorkerFactory(configuration: WorkerConfiguration): WorkerFactory {
  if (!cluster.isPrimary || Object.keys(cluster.workers ?? {}).length) throw Error('cluster-configuration-invalid');
  cluster.schedulingPolicy = cluster.SCHED_NONE;
  cluster.setupPrimary({ exec: new URL('./worker-process.mjs', import.meta.url).pathname, silent: true, execArgv: [] });
  return async (_index, fault) => {
    const worker = new ClusterWorker(configuration, fault); await worker.ready(); return worker;
  };
}
