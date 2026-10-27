import { createServer, type Server } from 'node:https';
import { createSecureContext, TLSSocket } from 'node:tls';
import { X509Certificate, createPrivateKey } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Socket, AddressInfo } from 'node:net';
import { ContractError, configurationDigest, validateManifest, type Manifest } from '../../../contracts/lib/index.ts';
import { monotonicRuntime, type LeaseRuntime, type WorkerLease } from './worker-lease.ts';
import type { CoordinatorResponse, RequestCoordinator } from './request-coordinator.ts';

type Connection = {
  raw: Socket; tls: TLSSocket | null; rawClosed: boolean; tlsClosed: boolean;
  accepted: bigint; headerDeadline: bigint; requestDeadline: bigint; started: boolean;
  writeFinished: boolean;
  cancelHeader: (() => void) | null; cancelRequest: (() => void) | null; client: AbortController;
};
export type GatewayTls = { key: string; cert: string };
type Coordinator = Pick<RequestCoordinator, 'binding' | 'handle' | 'close'>;

/** One worker's strict TLS1.3/HTTP1.1 ingress. One request per connection; no pipelining or keep-alive. */
export class HttpsGateway {
  readonly #manifest: Manifest;
  readonly #lease: WorkerLease;
  readonly #coordinator: Coordinator;
  readonly #runtime: LeaseRuntime;
  readonly #server: Server;
  readonly #connections = new Map<Socket, Connection>();
  readonly #tasks = new Set<Promise<void>>();
  readonly #onLeaseAbort: () => void;
  readonly #listenAbort = new AbortController();
  #closed = false;
  #listening = false;
  #starting = false;
  #lastNow = 0n;
  #drain: Promise<void> | null = null;
  #resolveDrain: (() => void) | null = null;
  #rejectDrain: ((error: Error) => void) | null = null;
  #serverClosed = true;
  #coordinatorClosed = false;
  #cleanupFailed = false;

  private constructor(m: Manifest, lease: WorkerLease, coordinator: Coordinator, tls: GatewayTls, runtime: LeaseRuntime) {
    this.#manifest = m; this.#lease = lease; this.#coordinator = coordinator; this.#runtime = runtime;
    const context = createSecureContext({ key: tls.key, cert: tls.cert, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' });
    this.#server = createServer({
      minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', handshakeTimeout: m.limits.gateway.tls_header_timeout_ms,
      SNICallback: (name, done) => name.toLowerCase() === m.origin_name ? done(null, context) : done(new Error('tls-host-not-allowed')),
      ALPNCallback: hello => hello.protocols.includes('http/1.1') ? 'http/1.1' : undefined,
      maxHeaderSize: m.limits.gateway.headers_max_bytes, requireHostHeader: true, insecureHTTPParser: false,
      headersTimeout: m.limits.gateway.tls_header_timeout_ms, requestTimeout: m.limits.gateway.request_timeout_ms,
      connectionsCheckingInterval: 1000,
    });
    // An empty default TLS context also prevents clients without SNI from selecting a certificate.
    this.#server.maxHeadersCount = 0; // Keep full bounded raw headers for the coordinator's count/duplicate checks.
    this.#server.prependListener('connection', (raw: Socket) => this.#accept(raw));
    this.#server.prependListener('secureConnection', (socket: TLSSocket) => this.#secure(socket));
    this.#server.on('request', (req, res) => this.#request(req, res));
    for (const event of ['checkContinue', 'checkExpectation'] as const) this.#server.on(event, (req, _res) => req.socket.destroy());
    this.#server.on('upgrade', (_req, socket) => socket.destroy());
    this.#server.on('connect', (_req, socket) => socket.destroy());
    this.#server.on('dropRequest', (_req, socket) => socket.destroy());
    this.#server.on('clientError', (_error, socket) => socket.destroy());
    this.#server.on('tlsClientError', (_error, socket) => socket.destroy());
    this.#server.on('error', () => { lease.requestClose('dependency-lost'); void this.close(); });
    this.#server.on('close', () => { this.#serverClosed = true; this.#listening = false; this.#settled(); });
    this.#onLeaseAbort = () => { void this.close(); };
    lease.signal.addEventListener('abort', this.#onLeaseAbort, { once: true });
    if (lease.signal.aborted) void this.close();
  }

  static prepare(configuration: unknown, lease: WorkerLease, coordinator: Coordinator, material: GatewayTls,
    runtime: LeaseRuntime = monotonicRuntime): HttpsGateway {
    try {
      const m = validateManifest(structuredClone(configuration)), digest = configurationDigest(m);
      for (const binding of [lease.status, coordinator.binding]) {
        if (binding.run_id !== m.run_id || binding.config_digest !== digest) throw Error('binding');
      }
      if (lease.signal.aborted || !['READY', 'ENABLED'].includes(lease.status.state) ||
        typeof material.key !== 'string' || material.key.length > 16384 || typeof material.cert !== 'string' || material.cert.length > 65536) throw Error('material');
      const cert = new X509Certificate(material.cert);
      if (!cert.checkHost(m.origin_name, { wildcards: false }) || !cert.checkPrivateKey(createPrivateKey(material.key))) throw Error('certificate');
      return new HttpsGateway(m, lease, coordinator, { key: material.key, cert: material.cert }, runtime);
    } catch { throw new ContractError('https-configuration-invalid'); }
  }

  get status() { return Object.freeze({ closed: this.#closed, listening: this.#listening, sockets: this.#connections.size, handlers: this.#tasks.size }); }

  /** Trusted startup configuration only. Production is private :443; tests use ephemeral loopback ports. */
  async listen(host = '0.0.0.0', port = 443): Promise<Readonly<AddressInfo>> {
    if (this.#closed || this.#starting || this.#listening) throw new ContractError('https-listen-unavailable');
    this.#starting = true; this.#serverClosed = false;
    try {
      await new Promise<void>((resolve, reject) => {
        const cleanup = () => { this.#server.off('error', error).off('close', canceled).off('listening', ready); };
        const error = () => { cleanup(); reject(new ContractError('https-listen-failed')); };
        const canceled = () => { cleanup(); reject(new ContractError('https-listen-failed')); };
        const ready = () => { cleanup(); resolve(); };
        this.#server.once('error', error).once('close', canceled).once('listening', ready)
          .listen({ port, host, signal: this.#listenAbort.signal });
      });
      if (this.#closed) { this.#stopListener(); throw Error('closed'); }
      this.#listening = true; return Object.freeze({ ...(this.#server.address() as AddressInfo) });
    } catch { if (!this.#server.listening) this.#serverClosed = true; this.#settled(); throw new ContractError('https-listen-failed'); }
    finally { this.#starting = false; this.#settled(); }
  }

  #now(): bigint | null {
    try {
      const now = this.#runtime.nowNs();
      if (typeof now !== 'bigint' || now < this.#lastNow || now < 0n || now > (1n << 64n) - 1n) throw Error('clock');
      this.#lastNow = now; return now;
    } catch { this.#lease.requestClose('clock-unsafe'); void this.close(); return null; }
  }

  #accept(raw: Socket): void {
    raw.on('error', () => raw.destroy());
    if (this.#closed || !this.#lease.checkActive() || this.#connections.size >= this.#manifest.limits.gateway.sockets_per_worker) { raw.destroy(); return; }
    const now = this.#now(); if (now === null) { raw.destroy(); return; }
    const record: Connection = { raw, tls: null, rawClosed: false, tlsClosed: true, accepted: now,
      headerDeadline: now + BigInt(this.#manifest.limits.gateway.tls_header_timeout_ms) * 1000000n,
      requestDeadline: now + BigInt(this.#manifest.limits.gateway.request_timeout_ms) * 1000000n,
      started: false, writeFinished: false, cancelHeader: null, cancelRequest: null, client: new AbortController() };
    this.#connections.set(raw, record);
    raw.once('close', () => { record.rawClosed = true; if (!record.writeFinished) record.client.abort(); this.#connectionDone(record); });
    this.#arm(record, false);
  }

  #find(socket: Socket): Connection | undefined {
    const matches = [...this.#connections.values()].filter(record => record.tls === socket || record.raw === socket ||
      (!record.tls && socket.remoteAddress !== undefined && socket.localAddress !== undefined &&
        record.raw.remoteAddress === socket.remoteAddress && record.raw.remotePort === socket.remotePort &&
        record.raw.localAddress === socket.localAddress && record.raw.localPort === socket.localPort));
    return matches.length === 1 ? matches[0] : undefined;
  }

  #secure(socket: TLSSocket): void {
    const record = this.#find(socket);
    socket.on('error', () => socket.destroy());
    if (!record || this.#closed || typeof socket.servername !== 'string' || socket.servername.toLowerCase() !== this.#manifest.origin_name || socket.getProtocol() !== 'TLSv1.3' ||
      (socket.alpnProtocol && socket.alpnProtocol !== 'http/1.1')) { socket.destroy(); return; }
    record.tls = socket; record.tlsClosed = false;
    socket.once('close', () => { record.tlsClosed = true; if (!record.writeFinished) record.client.abort(); record.raw.destroy(); this.#connectionDone(record); });
    const now = this.#now();
    if (now === null || now >= record.headerDeadline || !this.#lease.checkActive()) this.#destroy(record);
  }

  #destroy(record: Connection): void {
    record.client.abort(); record.tls?.destroy(); record.raw.destroy();
  }
  #connectionDone(record: Connection): void {
    if (!record.rawClosed || !record.tlsClosed) return;
    try { record.cancelHeader?.(); record.cancelRequest?.(); }
    catch { this.#cleanupFailed = true; this.#lease.requestClose('unsafe-state'); void this.close(); }
    record.cancelHeader = null; record.cancelRequest = null;
    this.#connections.delete(record.raw); this.#settled();
  }

  #arm(record: Connection, request: boolean): void {
    if (record.rawClosed || this.#closed) return;
    const now = this.#now(); if (now === null) return;
    const deadline = request ? record.requestDeadline : record.headerDeadline;
    if (now >= deadline) { this.#destroy(record); return; }
    try {
      const timer = this.#runtime.schedule(Number((deadline - now + 999999n) / 1000000n), () => {
        if (!request && record.started) return;
        this.#arm(record, request);
      });
      if (request) record.cancelRequest = timer; else record.cancelHeader = timer;
    } catch { this.#lease.requestClose('unsafe-state'); this.#destroy(record); }
  }

  #request(req: IncomingMessage, res: ServerResponse): void {
    const record = this.#find(req.socket);
    if (!record || !record.tls || record.tls !== req.socket || record.tlsClosed || record.started || this.#closed || req.httpVersion !== '1.1') { req.socket.destroy(); return; }
    record.started = true; res.shouldKeepAlive = false; res.sendDate = false;
    const now = this.#now();
    if (now === null || now >= record.headerDeadline || !this.#lease.checkActive()) { this.#destroy(record); return; }
    try { record.cancelHeader?.(); record.cancelHeader = null; } catch { this.#lease.requestClose('unsafe-state'); this.#destroy(record); return; }
    this.#arm(record, true);
    const hasBody = req.rawHeaders.some((name, index) => index % 2 === 0 &&
      (name.toLowerCase() === 'transfer-encoding' || (name.toLowerCase() === 'content-length' && req.rawHeaders[index + 1] !== '0')));
    req.once('aborted', () => this.#destroy(record));
    req.on('data', () => this.#destroy(record)); // No protected GET body is ever consumed or forwarded.
    const run = async () => {
      if (record.client.signal.aborted) return;
      await this.#coordinator.handle({ method: req.method ?? '', target: req.url ?? '', rawHeaders: req.rawHeaders,
        hasBody, signal: record.client.signal, checkActive: () => {
          const now = this.#now();
          if (this.#closed || record.client.signal.aborted || now === null || now >= record.requestDeadline || !this.#lease.checkActive()) {
            this.#destroy(record); return false;
          }
          return true;
        } }, (response, signal) => this.#write(record, res, response, signal));
      if (!res.writableFinished) this.#destroy(record);
    };
    // Valid zero-body framing must actually finish before any authorization work begins.
    const task = (async () => {
      if (!hasBody && !req.complete) await new Promise<void>(resolve => { req.once('end', resolve); record.client.signal.addEventListener('abort', () => resolve(), { once: true }); });
      await run();
    })();
    this.#tasks.add(task);
    task.catch(() => {
      if (!record.client.signal.aborted && !this.#closed) this.#lease.requestClose('unsafe-state');
      this.#destroy(record);
    }).finally(() => { this.#tasks.delete(task); this.#settled(); });
    req.resume();
  }

  #write(record: Connection, res: ServerResponse, response: CoordinatorResponse, signal: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = record.tls!;
      let finished = false, settled = false;
      const abort = () => this.#destroy(record);
      const live = () => {
        const now = this.#now();
        return !this.#closed && !signal.aborted && !record.client.signal.aborted && now !== null &&
          now < record.requestDeadline && this.#lease.checkActive();
      };
      const done = () => {
        if (settled) return; settled = true;
        const complete = finished && live();
        signal.removeEventListener('abort', abort); socket.off('close', done); res.off('error', abort); res.off('finish', finish);
        if (complete) resolve(); else reject(new ContractError('https-write-aborted'));
      };
      const finish = () => {
        if (!live()) { abort(); return; }
        finished = true; record.writeFinished = true;
      };
      socket.once('close', done); res.once('finish', finish); res.once('error', abort); signal.addEventListener('abort', abort, { once: true });
      const now = this.#now();
      if (socket.destroyed || signal.aborted || record.client.signal.aborted || this.#closed || now === null || now >= record.requestDeadline || !this.#lease.checkActive()) {
        abort(); if (record.tlsClosed) done(); return;
      }
      try {
        if ('kind' in response && response.kind === 'upstream-error') res.writeHead(response.status, { 'cache-control': 'no-store', 'content-length': '0', connection: 'close' }).end();
        else res.writeHead(response.status, { ...response.headers, connection: 'close' }).end(response.body);
      } catch { abort(); }
    });
  }

  #stopListener(): void {
    this.#listenAbort.abort();
    if (this.#server.listening) this.#server.close();
  }
  #settled(): void {
    if (!this.#closed || this.#starting || !this.#serverClosed || !this.#coordinatorClosed || this.#connections.size || this.#tasks.size) return;
    if (this.#cleanupFailed) this.#rejectDrain?.(new ContractError('https-close-failed')); else this.#resolveDrain?.();
  }

  /** Local listener/connection/handler/pipeline drain, not the all-worker/all-role reset barrier. */
  close(): Promise<void> {
    if (this.#drain) return this.#drain;
    this.#drain = new Promise<void>((resolve, reject) => { this.#resolveDrain = resolve; this.#rejectDrain = reject; });
    this.#drain.catch(() => {}); this.#closed = true;
    this.#lease.signal.removeEventListener('abort', this.#onLeaseAbort); this.#lease.fence();
    if (this.#server.listening || this.#starting) this.#stopListener();
    for (const record of this.#connections.values()) this.#destroy(record);
    try {
      this.#coordinator.close().then(() => { this.#coordinatorClosed = true; this.#settled(); }, () => { this.#cleanupFailed = true; this.#coordinatorClosed = true; this.#settled(); });
    } catch { this.#cleanupFailed = true; this.#coordinatorClosed = true; }
    this.#settled(); return this.#drain;
  }
}
