// Client role lifecycle (plan section 5): same state machine as the issuer, minus key/lease. A client holds its own
// plaintext vouchers and runs named scenarios one at a time. Scenario execution is asynchronous so STATUS and
// FENCE stay responsive; FENCE aborts the scenario, clears all credentials and returns only after it has settled.
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  PROTOCOL, ContractError, hex, validateControlRequest, validateControlResponse, type Manifest,
} from '../../../../contracts/lib/index.ts';
import { LabError, type ControlErrorResult } from '../errors.ts';
import { ClientVouchers } from './vouchers.ts';
import { LabClient } from './client.ts';

type State = 'FENCED' | 'PREPARED' | 'READY' | 'ENABLED' | 'CLOSING' | 'FAULTED';
type Fault = (typeof PROTOCOL.faults)[number] | null;
type Json = Record<string, unknown>;
type Counters = { issuance_successes: number; issuance_failures: number; observations: number };

export type ScenarioOutcome = {
  status: 'PASS' | 'FAIL' | 'INCONCLUSIVE';
  expected: string;
  counters?: Partial<Counters>;
  failure_labels?: string[];
};
export type ScenarioContext = { client: LabClient; manifest: Manifest; seed: number; signal: AbortSignal };
export type ScenarioRunner = (ctx: ScenarioContext) => Promise<ScenarioOutcome>;

/** The frozen scenario list is implemented incrementally (M05); this is the only one that exists at G1. */
export const baseScenarios: Record<string, ScenarioRunner> = {
  'healthy-flow': async ({ client }) => {
    const challenge = await client.fetchChallenge();
    await client.obtainToken(challenge);
    const result = await client.redeem(challenge.epoch);
    return { status: result.status === 200 ? 'PASS' : 'FAIL', expected: 'accepted',
      counters: { issuance_successes: 1, observations: 1 }, failure_labels: result.status === 200 ? [] : ['token-invalid'] };
  },
};

export type ClientRoleOptions = {
  readSecret?: (path: string) => Buffer;
  /** Proxy to dial; defaults to the manifest's proxy endpoint. */
  proxy?: { host: string; port: number };
  scenarios?: Record<string, ScenarioRunner>;
  drainMs?: number;
};

export class ClientRole {
  readonly incarnation = hex(randomBytes(16));
  readonly #readSecret: (path: string) => Buffer;
  readonly #proxyOverride: { host: string; port: number } | undefined;
  readonly #scenarios: Record<string, ScenarioRunner>;
  readonly #drainMs: number;
  #state: State = 'FENCED';
  #fault: Fault = null;
  #runClosed = false;
  #runId: string | null = null;
  #digest: string | null = null;
  #manifest: Manifest | null = null;
  #clientId: string | null = null;
  #caPem: string | null = null;
  #vouchers: ClientVouchers | null = null;
  #client: LabClient | null = null;
  #running: { promise: Promise<unknown>; abort: AbortController } | null = null;
  #counters: Counters = { issuance_successes: 0, issuance_failures: 0, observations: 0 };
  #chain: Promise<unknown> = Promise.resolve();

  constructor(options: ClientRoleOptions = {}) {
    this.#readSecret = options.readSecret ?? ((p) => readFileSync(p));
    this.#proxyOverride = options.proxy;
    this.#scenarios = options.scenarios ?? baseScenarios;
    this.#drainMs = options.drainMs ?? 8000;
  }
  get state(): State { return this.#state; }

  async handle(raw: unknown): Promise<Json> {
    const id = (raw as { request_id?: unknown } | null)?.request_id;
    const requestId = typeof id === 'string' && /^[0-9a-f]{32}$/.test(id) ? id : '0'.repeat(32);
    try {
      if ((raw as { version?: unknown } | null)?.version !== 1) throw new LabError('BAD_VERSION');
      let req: Json;
      try { req = validateControlRequest(raw); } catch (e) { if (e instanceof ContractError) throw new LabError('BAD_MESSAGE'); throw e; }
      const command = req['command'] as string;
      if (['CREATE_ISSUER_KEY', 'PROVISION_VOUCHERS', 'HEARTBEAT'].includes(command)) throw new LabError('ILLEGAL_STATE'); // not client commands
      this.#checkEnvelope(req, command);
      if (command === 'STATUS') return this.#ok(requestId, 'STATUS', { ready: this.#state === 'READY' || this.#state === 'ENABLED', run_closed: this.#runClosed, fault: this.#fault });
      if (command === 'REPORT') return this.#report(requestId);
      if (command === 'FENCE') return await this.#fence(requestId, (req['payload'] as Json)['reason'] as Fault);
      if (command === 'RUN_SCENARIO') return await this.#runScenario(requestId, req['payload'] as Json);
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
    // A fresh client learns its run from PREPARE_RUN; every later command must match it.
    if (command === 'PREPARE_RUN' && this.#runId === null) return;
    if (req['run_id'] !== this.#runId) throw new LabError('WRONG_RUN');
    if (command !== 'PREPARE_RUN' && req['config_digest'] !== this.#digest) throw new LabError('WRONG_CONFIG');
  }

  #mutate(requestId: string, command: string, req: Json): Json {
    try {
      switch (command) {
        case 'PREPARE_RUN': return this.#prepare(requestId, req['run_id'] as string, req['payload'] as Json);
        case 'PROVISION_CLIENT': return this.#provision(requestId, req['payload'] as never);
        case 'CHECK_READY': return this.#checkReady(requestId);
        case 'ENABLE': return this.#enable(requestId);
        default: throw new LabError('ILLEGAL_STATE'); // issuer/gateway commands do not belong to a client
      }
    } catch (e) {
      if (e instanceof LabError) return this.#error(requestId, e.result);
      this.#faultNow('unsafe-state');
      return this.#error(requestId, 'FAULTED');
    }
  }

  #prepare(requestId: string, runId: string, payload: Json): Json {
    if (this.#state !== 'FENCED' || this.#runClosed || this.#digest !== null) throw new LabError('ILLEGAL_STATE');
    if (payload['role'] !== 'client') throw new LabError('BAD_MESSAGE');
    const manifest = payload['manifest'] as Manifest;
    const cfg = payload['role_config'] as { client_id?: string; ca_cert_path?: string };
    if (!cfg.client_id || !cfg.ca_cert_path) throw new LabError('BAD_MESSAGE');
    try { this.#caPem = this.#readSecret(cfg.ca_cert_path).toString('utf8'); } catch { throw new LabError('DEPENDENCY_UNAVAILABLE'); }
    const proxy = this.#proxyOverride ?? (() => { const u = new URL(manifest.endpoints.proxy_http); return { host: u.hostname, port: Number(u.port) }; })();
    this.#runId = runId;
    this.#manifest = manifest;
    this.#clientId = cfg.client_id;
    this.#digest = payload['proposed_config_digest'] as string;
    this.#vouchers = new ClientVouchers(manifest.limits.client.inventory_max);
    this.#client = new LabClient({ manifest, proxy, caPem: this.#caPem, vouchers: this.#vouchers });
    this.#state = 'PREPARED';
    return this.#ok(requestId, 'PREPARED', {});
  }

  #provision(requestId: string, payload: Parameters<ClientVouchers['provision']>[0]): Json {
    if (this.#state !== 'PREPARED' || !this.#vouchers) throw new LabError('ILLEGAL_STATE');
    return this.#ok(requestId, 'PROVISIONED', this.#vouchers.provision(payload));
  }

  #checkReady(requestId: string): Json {
    if (this.#state === 'READY') return this.#ok(requestId, 'READY', { workers_ready: 1 });
    if (this.#state !== 'PREPARED' || !this.#vouchers?.sealed) throw new LabError('ILLEGAL_STATE');
    this.#state = 'READY';
    return this.#ok(requestId, 'READY', { workers_ready: 1 });
  }

  #enable(requestId: string): Json {
    if (this.#state === 'ENABLED') return this.#ok(requestId, 'ENABLED', { workers_enabled: 1 });
    if (this.#state !== 'READY' || !this.#vouchers) throw new LabError('ILLEGAL_STATE');
    this.#vouchers.lock();
    this.#state = 'ENABLED';
    return this.#ok(requestId, 'ENABLED', { workers_enabled: 1 });
  }

  async #runScenario(requestId: string, payload: Json): Promise<Json> {
    if (this.#state !== 'ENABLED' || !this.#client || !this.#manifest) throw new LabError('ILLEGAL_STATE');
    if (this.#running) throw new LabError('ILLEGAL_STATE'); // at most one scenario per client
    const scenarioId = payload['scenario_id'] as string;
    const runner = this.#scenarios[scenarioId];
    if (!runner) throw new LabError('ILLEGAL_STATE'); // frozen name, not implemented yet: never fake a result
    const abort = new AbortController();
    const settled = (async (): Promise<ScenarioOutcome> => {
      try { return await runner({ client: this.#client!, manifest: this.#manifest!, seed: payload['schedule_seed'] as number, signal: abort.signal }); }
      catch { return { status: 'FAIL', expected: 'accepted', failure_labels: ['authorization-unavailable'] }; }
    })();
    this.#running = { promise: settled, abort };
    let outcome: ScenarioOutcome;
    try { outcome = await settled; } finally { this.#running = null; }
    if (abort.signal.aborted || this.#state !== 'ENABLED') throw new LabError('FAULTED'); // fenced mid-scenario: no result
    for (const k of Object.keys(this.#counters) as (keyof Counters)[]) this.#counters[k] += outcome.counters?.[k] ?? 0;
    return this.#ok(requestId, 'SCENARIO_COMPLETE', {
      scenario_id: scenarioId, status: outcome.status, expected: outcome.expected,
      counters: { ...outcome.counters }, origin_counts_available: false, worker_verification_attempts: [],
      failure_labels: outcome.failure_labels ?? [],
    });
  }

  #faultNow(reason: Fault): void {
    if (this.#state !== 'FAULTED') { this.#state = 'FAULTED'; this.#fault = reason; }
    this.#runClosed = true;
    this.#teardown();
  }

  #teardown(): void {
    this.#running?.abort.abort();
    this.#client?.close(); // destroys sockets (aborting in-flight requests) and clears tokens and vouchers
  }

  async #fence(requestId: string, reason: Fault): Promise<Json> {
    const hadRun = this.#runId !== null;
    this.#state = this.#state === 'FAULTED' ? 'FAULTED' : 'CLOSING';
    this.#teardown();
    const running = this.#running?.promise;
    if (running) {
      const settled = await Promise.race([running.then(() => true), new Promise<boolean>((r) => setTimeout(() => r(false), this.#drainMs).unref())]);
      if (!settled) return this.#error(requestId, 'FAULTED'); // cannot confirm: the controller must kill this process
    }
    if (hadRun) { this.#runClosed = true; this.#fault = this.#fault ?? reason; }
    this.#state = 'FENCED';
    return this.#ok(requestId, 'FENCED', {});
  }

  #report(requestId: string): Json {
    return this.#ok(requestId, 'REPORT', {
      counters: { ...this.#counters }, measurements: [], same_source_observed: null, origin_counts_available: false, worker_verification_attempts: [],
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
