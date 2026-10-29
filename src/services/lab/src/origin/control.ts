// Private protected origin (plan sections 4.1, 5.5). Three independent aggregate counters, never reset within a run:
//   protected_requests_received  incremented for every fully parsed request to the protected route, BEFORE the
//                                generation check (so a wrong-generation request still counts as an arrival)
//   generation_mismatches        wrong/missing/duplicate X-TokenForge-Run
//   resources_served             only when the resource was actually served
// "Origin arrival" always means received. The internal run header is generation attribution inside a trusted
// private network, not authorization.
import { randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  PROTOCOL, ContractError, hex, validateControlRequest, validateControlResponse, type Manifest,
} from '../../../../contracts/lib/index.ts';
import { LabError, type ControlErrorResult } from '../errors.ts';

type State = 'FENCED' | 'PREPARED' | 'READY' | 'ENABLED' | 'CLOSING' | 'FAULTED';
type Fault = (typeof PROTOCOL.faults)[number] | null;
type Json = Record<string, unknown>;

export const RUN_HEADER = 'x-tokenforge-run';
const ROUTE = new URL(PROTOCOL.endpoints.origin_http).pathname;
const BODY = Buffer.alloc(1024, 0x61); // deterministic, well under origin_body_max_bytes

export type OriginRoleOptions = { listen?: { host: string; port: number }; drainMs?: number };

export class OriginRole {
  readonly incarnation = hex(randomBytes(16));
  readonly #listen: { host: string; port: number };
  readonly #drainMs: number;
  #state: State = 'FENCED';
  #fault: Fault = null;
  #runClosed = false;
  #runId: string | null = null;
  #digest: string | null = null;
  #server: Server | null = null;
  #active = 0;
  #idle: (() => void)[] = [];
  readonly #counters = { protected_requests_received: 0, generation_mismatches: 0, resources_served: 0 };
  #chain: Promise<unknown> = Promise.resolve();

  constructor(options: OriginRoleOptions = {}) {
    this.#listen = options.listen ?? { host: '127.0.0.1', port: Number(PROTOCOL.endpoints.origin_http.match(/:(\d+)\//)![1]) };
    this.#drainMs = options.drainMs ?? 5000;
  }
  get state(): State { return this.#state; }
  get address(): AddressInfo | null { return (this.#server?.address() as AddressInfo | null) ?? null; }

  async handle(raw: unknown): Promise<Json> {
    const id = (raw as { request_id?: unknown } | null)?.request_id;
    const requestId = typeof id === 'string' && /^[0-9a-f]{32}$/.test(id) ? id : '0'.repeat(32);
    try {
      if ((raw as { version?: unknown } | null)?.version !== 1) throw new LabError('BAD_VERSION');
      let req: Json;
      try { req = validateControlRequest(raw); } catch (e) { if (e instanceof ContractError) throw new LabError('BAD_MESSAGE'); throw e; }
      const command = req['command'] as string;
      if (['CREATE_ISSUER_KEY', 'PROVISION_VOUCHERS', 'PROVISION_CLIENT', 'HEARTBEAT', 'RUN_SCENARIO'].includes(command)) throw new LabError('ILLEGAL_STATE');
      this.#checkEnvelope(req, command);
      if (command === 'STATUS') return this.#ok(requestId, 'STATUS', { ready: this.#state === 'READY' || this.#state === 'ENABLED', run_closed: this.#runClosed, fault: this.#fault });
      if (command === 'REPORT') return this.#report(requestId);
      if (command === 'FENCE') return await this.#fence(requestId, (req['payload'] as Json)['reason'] as Fault);
      const run = this.#chain.then(() => this.#mutate(requestId, command, req), () => this.#mutate(requestId, command, req));
      this.#chain = run.catch(() => undefined);
      return await run;
    } catch (e) {
      return this.#error(requestId, e instanceof LabError ? e.result : 'FAULTED');
    }
  }

  #checkEnvelope(req: Json, command: string): void {
    const discovery = command === 'STATUS' || command === 'FENCE';
    const target = req['target_incarnation'] as string | null;
    if (target === null ? !discovery : target !== this.incarnation) throw new LabError('WRONG_INCARNATION');
    if (discovery) return;
    if (command === 'PREPARE_RUN' && this.#runId === null) return;
    if (req['run_id'] !== this.#runId) throw new LabError('WRONG_RUN');
    if (command !== 'PREPARE_RUN' && req['config_digest'] !== this.#digest) throw new LabError('WRONG_CONFIG');
  }

  async #mutate(requestId: string, command: string, req: Json): Promise<Json> {
    try {
      switch (command) {
        case 'PREPARE_RUN': return this.#prepare(requestId, req['run_id'] as string, req['payload'] as Json);
        case 'CHECK_READY':
          if (this.#state === 'READY') return this.#ok(requestId, 'READY', { workers_ready: 1 });
          if (this.#state !== 'PREPARED') throw new LabError('ILLEGAL_STATE');
          this.#state = 'READY';
          return this.#ok(requestId, 'READY', { workers_ready: 1 });
        case 'ENABLE': return await this.#enable(requestId);
        default: throw new LabError('ILLEGAL_STATE');
      }
    } catch (e) {
      if (e instanceof LabError) return this.#error(requestId, e.result);
      this.#faultNow('unsafe-state');
      return this.#error(requestId, 'FAULTED');
    }
  }

  #prepare(requestId: string, runId: string, payload: Json): Json {
    if (this.#state !== 'FENCED' || this.#runClosed || this.#digest !== null) throw new LabError('ILLEGAL_STATE');
    if (payload['role'] !== 'origin') throw new LabError('BAD_MESSAGE');
    const manifest = payload['manifest'] as Manifest;
    if (manifest.run_id !== runId) throw new LabError('WRONG_RUN');
    this.#runId = runId;
    this.#digest = payload['proposed_config_digest'] as string;
    this.#state = 'PREPARED';
    return this.#ok(requestId, 'PREPARED', {});
  }

  async #enable(requestId: string): Promise<Json> {
    if (this.#state === 'ENABLED') return this.#ok(requestId, 'ENABLED', { workers_enabled: 1 });
    if (this.#state !== 'READY') throw new LabError('ILLEGAL_STATE');
    const server = createServer({ maxHeaderSize: PROTOCOL.gateway_common.headers_max_bytes, keepAliveTimeout: PROTOCOL.gateway_common.origin_keepalive_ms,
      requestTimeout: PROTOCOL.gateway_common.request_timeout_ms }, (req, res) => this.#serve(req, res));
    server.maxHeadersCount = PROTOCOL.gateway_common.headers_max_count + 1;
    server.on('clientError', (_e, socket) => socket.destroy());
    this.#server = server;
    try { await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(this.#listen.port, this.#listen.host, () => resolve()); }); }
    catch { this.#faultNow('dependency-lost'); throw new LabError('FAULTED'); }
    if (this.#state !== 'READY') { server.closeAllConnections(); server.close(); throw new LabError('FAULTED'); } // fenced while binding
    this.#state = 'ENABLED';
    return this.#ok(requestId, 'ENABLED', { workers_enabled: 1 });
  }

  #serve(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse): void {
    this.#active += 1;
    res.on('close', () => { this.#active -= 1; if (this.#active === 0) for (const wake of this.#idle.splice(0)) wake(); });
    if (this.#state !== 'ENABLED') { res.writeHead(503, { Connection: 'close', 'Content-Length': '0' }); res.end(); return; }
    if (req.url !== ROUTE) { res.writeHead(404, { 'Content-Length': '0' }); res.end(); return; }
    req.resume();
    this.#counters.protected_requests_received += 1; // before any generation validation
    const values: string[] = [];
    for (let i = 0; i + 1 < req.rawHeaders.length; i += 2) if (req.rawHeaders[i]!.toLowerCase() === RUN_HEADER) values.push(req.rawHeaders[i + 1]!);
    if (values.length !== 1 || values[0] !== this.#runId) {
      this.#counters.generation_mismatches += 1;
      res.writeHead(421, { 'Content-Length': '0', 'Cache-Control': 'no-store' }); res.end(); return;
    }
    if (req.method !== 'GET') { res.writeHead(405, { Allow: 'GET', 'Content-Length': '0', 'Cache-Control': 'no-store' }); res.end(); return; }
    this.#counters.resources_served += 1;
    res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': String(BODY.length), 'Cache-Control': 'no-store' });
    res.end(BODY);
  }

  #faultNow(reason: Fault): void {
    if (this.#state !== 'FAULTED') { this.#state = 'FAULTED'; this.#fault = reason; }
    this.#runClosed = true;
    this.#server?.closeAllConnections();
    this.#server?.close();
  }

  async #fence(requestId: string, reason: Fault): Promise<Json> {
    const hadRun = this.#runId !== null;
    this.#state = this.#state === 'FAULTED' ? 'FAULTED' : 'CLOSING';
    const server = this.#server;
    if (server) { server.close(); server.closeAllConnections(); }
    if (this.#active > 0) {
      const settled = await new Promise<boolean>((resolve) => {
        const timer = setTimeout(() => resolve(false), this.#drainMs);
        this.#idle.push(() => { clearTimeout(timer); resolve(true); });
      });
      if (!settled) return this.#error(requestId, 'FAULTED'); // cannot confirm handlers settled: the controller must kill us
    }
    if (hadRun) { this.#runClosed = true; this.#fault = this.#fault ?? reason; }
    this.#state = 'FENCED';
    return this.#ok(requestId, 'FENCED', {});
  }

  /** Counts are final (settled) unless a handler is still running; then they are reported unavailable, never as a guess. */
  #report(requestId: string): Json {
    return this.#ok(requestId, 'REPORT', {
      counters: { ...this.#counters }, measurements: [], same_source_observed: null,
      origin_counts_available: this.#active === 0, worker_verification_attempts: [],
    });
  }

  #ok(requestId: string, result: string, data: Json): Json {
    const reply = { version: 1, request_id: requestId, state: this.#state, run_id: this.#runId, config_digest: this.#digest, incarnation: this.incarnation, ok: true, result, data };
    validateControlResponse(reply);
    return reply;
  }
  #error(requestId: string, result: ControlErrorResult): Json {
    const reply = { version: 1, request_id: requestId, state: this.#state, run_id: this.#runId, config_digest: this.#digest, incarnation: this.incarnation, ok: false, result, data: {} };
    validateControlResponse(reply);
    return reply;
  }
}
