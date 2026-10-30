import { Agent, request, type ClientRequest, type ClientRequestArgs, type IncomingMessage } from 'node:http';
import { createConnection, type Socket } from 'node:net';
import type { Duplex } from 'node:stream';
import { ContractError, configurationDigest, validateManifest, type Manifest } from '../../../contracts/lib/index.ts';
import type { FlowPermit } from './flow-admission.ts';
import type { LeaseRuntime, WorkerLease } from './worker-lease.ts';

/** Internal transport seam for controlled tests; never selected by headers, URLs or environment flags. */
export interface OriginRuntime extends LeaseRuntime { connect(endpoint: { host: string; port: number }): Socket }
const runtimeDefault: OriginRuntime = {
  nowNs: () => process.hrtime.bigint(), connect: endpoint => createConnection(endpoint),
  schedule(ms, fn) { const timer = setTimeout(fn, ms); return () => clearTimeout(timer); },
};
export type OriginResult = { kind: 'response'; status: 200; headers: Readonly<Record<string, string>>; body: Uint8Array } |
  { kind: 'upstream-error'; status: 502 | 504 } | { kind: 'unavailable' } | { kind: 'canceled' } | { kind: 'busy' };
const unavailable: OriginResult = Object.freeze({ kind: 'unavailable' });
const canceled: OriginResult = Object.freeze({ kind: 'canceled' });
const failed: OriginResult = Object.freeze({ kind: 'upstream-error', status: 502 });
const timedOut: OriginResult = Object.freeze({ kind: 'upstream-error', status: 504 });
type Job = { stop(result: OriginResult): void };

class OriginAgent extends Agent {
  readonly connectSocket: () => Socket;
  readonly assign: (socket: Socket) => void;
  constructor(limit: number, idleMs: number, connect: () => Socket, assign: (socket: Socket) => void) {
    super({ keepAlive: true, maxSockets: limit, maxTotalSockets: limit, maxFreeSockets: limit,
      timeout: idleMs, scheduling: 'lifo', proxyEnv: {} });
    this.connectSocket = connect; this.assign = assign;
  }
  override createConnection(_options: ClientRequestArgs): Socket {
    const socket = this.connectSocket(); this.assign(socket); return socket;
  }
  override reuseSocket(socket: Duplex, req: ClientRequest): void {
    super.reuseSocket(socket, req);
    const tcp = socket as Socket; tcp.setTimeout(0); this.assign(tcp);
  }
}

/** Fixed upstream I/O only. Caller must obtain a successful atomic claim BEFORE calling forwardAfterClaim.
 * This component cannot prove that precondition from a structural claim object.
 */
export class FixedOrigin {
  readonly #manifest: Manifest;
  readonly #lease: WorkerLease;
  readonly #runtime: OriginRuntime;
  readonly #agent: OriginAgent;
  readonly #sockets = new Set<Socket>();
  readonly #jobs = new Set<Job>();
  readonly #used = new WeakSet<FlowPermit>();
  readonly #onLeaseAbort: () => void;
  #assigning: ((socket: Socket) => void) | null = null;
  #closed = false;
  #lastNow = 0n;
  #drain: Promise<void> | null = null;
  #resolveDrain: (() => void) | null = null;

  private constructor(m: Manifest, lease: WorkerLease, runtime: OriginRuntime) {
    this.#manifest = m; this.#lease = lease; this.#runtime = runtime;
    const origin = new URL(m.endpoints.origin_http);
    this.#agent = new OriginAgent(m.limits.gateway.origin_sockets_per_worker, m.limits.gateway.origin_free_idle_ms,
      () => runtime.connect({ host: origin.hostname, port: Number(origin.port) }), socket => {
        if (!this.#sockets.has(socket)) {
          this.#sockets.add(socket);
          socket.once('close', () => { this.#sockets.delete(socket); this.#settled(); });
        }
        this.#assigning?.(socket);
        socket.setTimeout(0);
        if (this.#closed) socket.destroy();
      });
    this.#onLeaseAbort = () => { void this.close(); };
    lease.signal.addEventListener('abort', this.#onLeaseAbort, { once: true });
    if (lease.signal.aborted) void this.close();
  }

  static prepare(configuration: unknown, lease: WorkerLease, runtime: OriginRuntime = runtimeDefault): FixedOrigin {
    try {
      const m = validateManifest(structuredClone(configuration));
      if (lease.status.run_id !== m.run_id || lease.status.config_digest !== configurationDigest(m)) throw Error('identity');
      return new FixedOrigin(m, lease, runtime);
    } catch { throw new ContractError('origin-configuration-invalid'); }
  }

  get status() {
    return Object.freeze({ closed: this.#closed, active: this.#jobs.size, sockets: this.#sockets.size,
      idle: Object.values(this.#agent.freeSockets).reduce((n, sockets) => n + (sockets?.length ?? 0), 0),
      queued: Object.values(this.#agent.requests).reduce((n, requests) => n + (requests?.length ?? 0), 0) });
  }
  get binding() { return Object.freeze({ run_id: this.#manifest.run_id, config_digest: configurationDigest(this.#manifest) }); }

  #now(): bigint | null {
    try {
      const now = this.#runtime.nowNs();
      if (typeof now !== 'bigint' || now < this.#lastNow || now < 0n || now > (1n << 64n) - 1n) throw Error('clock');
      this.#lastNow = now; return now;
    } catch { this.#lease.requestClose('clock-unsafe'); void this.close(); return null; }
  }
  #live(permit: FlowPermit): boolean { return !this.#closed && this.#lease.checkActive() && permit.checkActive() && !permit.signal.aborted && !this.#closed; }
  #settled(): void { if (this.#closed && this.#jobs.size === 0 && this.#sockets.size === 0) this.#resolveDrain?.(); }

  forwardAfterClaim(permit: FlowPermit): Promise<OriginResult> {
    if (this.#used.has(permit)) return Promise.resolve(unavailable);
    this.#used.add(permit); // An attempted call, including preflight failure, can never be retried with this permit.
    if (!this.#live(permit)) return Promise.resolve(permit.signal.aborted && !this.#closed ? canceled : unavailable);
    if (this.#jobs.size >= this.#manifest.limits.gateway.origin_sockets_per_worker) return Promise.resolve({ kind: 'busy' });
    const start = this.#now(); if (start === null) return Promise.resolve(unavailable);
    const deadline = start + BigInt(this.#manifest.limits.gateway.origin_timeout_ms) * 1000000n;
    if (deadline > (1n << 64n) - 1n) { this.#lease.requestClose('clock-unsafe'); return Promise.resolve(unavailable); }
    return new Promise(resolve => {
      let req: ClientRequest | null = null, res: IncomingMessage | null = null, socket: Socket | null = null;
      let socketClosed = false, requestClosed = false, ended = false, finished = false, scheduled = false;
      let outcome: OriginResult | null = null, cancelTimer: (() => void) | null = null, bytes = 0;
      let sent = false;
      const body = Buffer.alloc(this.#manifest.limits.gateway.origin_body_max_bytes);
      const check = (): OriginResult | null => {
        if (!this.#live(permit)) return this.#closed || this.#lease.status.run_closed ? unavailable : canceled;
        const now = this.#now(); return now === null ? unavailable : now >= deadline ? timedOut : null;
      };
      const finish = () => {
        if (finished || scheduled || !requestClosed || (outcome && socket && !socketClosed) || (!outcome && !ended)) return;
        scheduled = true;
        // Node emits request close BEFORE Agent's free event in the same tick.
        // Retain the slot until that transition has completed, so no hidden Agent queue forms.
        setImmediate(() => {
          scheduled = false;
          if (finished) return;
          // A short server keep-alive hint may make Agent destroy a completed
          // socket during its free transition. Retain capacity until close.
          if (!outcome && socket?.destroyed && !socketClosed) return;
          if (!outcome) {
            const unsafe = check();
            if (unsafe) { stop(unsafe); return; }
          }
          if (outcome && socket && !socketClosed) return;
          const cancel = cancelTimer; cancelTimer = null;
          try { cancel?.(); }
          catch { outcome ??= unavailable; this.#lease.requestClose('unsafe-state'); stop(unavailable); return; }
          finished = true;
          permit.signal.removeEventListener('abort', onAbort);
          socket?.removeListener('close', onSocketClose);
          socket?.removeListener('connect', send);
          this.#jobs.delete(job); this.#settled();
          resolve(outcome ?? { kind: 'response', status: 200, headers: Object.freeze({ 'cache-control': 'no-store',
            'content-type': 'application/octet-stream', 'content-length': String(bytes), 'x-content-type-options': 'nosniff' }),
            body: Buffer.from(body.subarray(0, bytes)) });
        });
      };
      const stop = (result: OriginResult) => {
        if (finished) return;
        outcome ??= result;
        res?.destroy(); req?.destroy(); socket?.destroy();
        finish();
      };
      const onSocketClose = () => { socketClosed = true; if (!ended && !outcome) outcome = failed; finish(); };
      const onAbort = () => stop(this.#closed || this.#lease.status.run_closed ? unavailable : canceled);
      const send = () => {
        if (sent || outcome || !req) return;
        const unsafe = check();
        if (unsafe) { stop(unsafe); return; }
        sent = true; req.end(); // Check at connect/reuse, not before buffering through delayed DNS/connect.
      };
      const armDeadline = () => {
        if (finished || outcome) return;
        const now = this.#now();
        if (now === null) { stop(unavailable); return; }
        if (now >= deadline) { stop(timedOut); return; }
        try { cancelTimer = this.#runtime.schedule(Number((deadline - now + 999999n) / 1000000n), armDeadline); }
        catch { this.#lease.requestClose('unsafe-state'); stop(unavailable); }
      };
      const job: Job = { stop }; this.#jobs.add(job);
      permit.signal.addEventListener('abort', onAbort, { once: true });
      try {
        armDeadline();
        if (outcome || this.#closed) { requestClosed = true; finish(); return; }
        this.#assigning = assigned => { socket = assigned; socket.once('close', onSocketClose); };
        req = request(this.#manifest.endpoints.origin_http, { agent: this.#agent, method: 'GET',
          maxHeaderSize: this.#manifest.limits.gateway.headers_max_bytes,
          headers: { 'X-TokenForge-Run': this.#manifest.run_id } });
        this.#assigning = null;
        req.maxHeadersCount = 0; // Preserve bounded raw headers for explicit field-count validation, never silently truncate.
        req.once('error', () => stop(failed));
        req.once('close', () => { requestClosed = true; finish(); });
        req.once('upgrade', (_response, upgraded) => { upgraded.destroy(); stop(failed); });
        req.once('information', () => stop(failed));
        req.once('response', response => {
          res = response;
          res.on('error', () => stop(failed)); res.once('aborted', () => stop(failed));
          if (outcome) { stop(outcome); return; }
          if (res.statusCode !== 200 || res.rawHeaders.length > this.#manifest.limits.gateway.headers_max_count * 2) { stop(failed); return; }
          res.on('data', (chunk: Buffer) => {
            const unsafe = check(); if (unsafe) { stop(unsafe); return; }
            if (outcome) return;
            if (bytes + chunk.length > body.length) { stop(failed); return; }
            chunk.copy(body, bytes); bytes += chunk.length;
          });
          res.once('end', () => {
            if (!response.complete) { stop(failed); return; }
            ended = true; finish();
          });
        });
        // The fixed pool has no request queue: an unexpected Agent transition fails closed before any bytes are sent.
        if (this.status.queued !== 0) { stop(failed); }
        if (socket && (socket as Socket).connecting) (socket as Socket).once('connect', send);
        else send();
      } catch {
        this.#assigning = null;
        if (!req) requestClosed = true;
        stop(failed);
      }
    });
  }

  /** Terminal pool shutdown; waits for tracked sockets AND attempts, not the whole gateway reset barrier. */
  close(): Promise<void> {
    if (!this.#drain) this.#drain = new Promise(resolve => { this.#resolveDrain = resolve; });
    if (!this.#closed) {
      this.#closed = true; this.#lease.signal.removeEventListener('abort', this.#onLeaseAbort);
      for (const job of this.#jobs) job.stop(unavailable);
      this.#agent.destroy(); for (const socket of this.#sockets) socket.destroy();
    }
    this.#settled(); return this.#drain;
  }
}
