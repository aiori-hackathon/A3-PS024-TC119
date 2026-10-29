// In-process stand-ins for a controller run: REAL issuer, origin and client roles; a scriptable gateway and replay store.
// Everything the controller sends is logged (command, role, ordering) so tests can assert order without exposing content.
import { randomBytes } from 'node:crypto';
import { PROTOCOL, hex, validateControlRequest, validateControlResponse, type Manifest } from '../../../../contracts/lib/index.ts';
import { IssuerRole } from '../../src/issuer/control.ts';
import { OriginRole } from '../../src/origin/control.ts';
import { ClientRole } from '../../src/client/control.ts';
import { InProcessLink } from '../../src/controller/link.ts';
import { CLIENT_IDS, type ClientId, type Json, type RedisPort, type ResetPort, type RoleLink, type RoleName } from '../../src/controller/ports.ts';
import { emergencyFence } from '../../src/controller/envelope.ts';
import type { RunLinks } from '../../src/controller/run.ts';
import { createPki } from './pki.ts';

export type LogEntry = { at: number; role: string; command: string; payload: Json };

/** Wraps a link so every request is recorded before it is sent. */
export class LoggedLink implements RoleLink {
  readonly role: RoleName;
  readonly inner: RoleLink;
  readonly log: LogEntry[];
  constructor(inner: RoleLink, log: LogEntry[]) { this.inner = inner; this.role = inner.role; this.log = log; }
  send(request: Json, timeoutMs?: number): Promise<Json> {
    this.log.push({ at: this.log.length, role: this.role, command: request['command'], payload: structuredClone(request['payload']) });
    return this.inner.send(request, timeoutMs);
  }
  close(): void { this.inner.close(); }
}

/** A gateway that obeys the control contract but whose behavior tests can bend. */
export class FakeGateway {
  readonly incarnation = hex(randomBytes(16));
  state: 'FENCED' | 'PREPARED' | 'READY' | 'ENABLED' = 'FENCED';
  runId: string | null = null; digest: string | null = null; runClosed = false;
  workers = 2;
  heartbeats: number[] = [];
  concurrent = 0; maxConcurrent = 0;
  ackDelayMs = 0; dropAcks = false; badSeq = false; failCommand: string | null = null;
  async handle(raw: unknown): Promise<Json> {
    const req = validateControlRequest(raw);
    const c = req['command'] as string;
    const ok = (result: string, data: Json) => this.#reply(req, true, result, data);
    if (this.failCommand === c) return this.#reply(req, false, 'ILLEGAL_STATE', {});
    switch (c) {
      case 'STATUS': return ok('STATUS', { ready: this.state === 'READY' || this.state === 'ENABLED', run_closed: this.runClosed, fault: null });
      case 'PREPARE_RUN': this.runId = req['run_id'] as string; this.digest = (req['payload'] as Json)['proposed_config_digest']; this.state = 'PREPARED'; return ok('PREPARED', {});
      case 'CHECK_READY': this.state = 'READY'; return ok('READY', { workers_ready: this.workers });
      case 'ENABLE': this.state = 'ENABLED'; return ok('ENABLED', { workers_enabled: this.workers });
      case 'HEARTBEAT': {
        const seq = (req['payload'] as Json)['seq'] as number;
        this.heartbeats.push(seq);
        this.concurrent += 1; this.maxConcurrent = Math.max(this.maxConcurrent, this.concurrent);
        try {
          if (this.dropAcks) await new Promise(() => undefined);
          if (this.ackDelayMs) await new Promise((r) => setTimeout(r, this.ackDelayMs));
        } finally { this.concurrent -= 1; }
        return ok('HEARTBEAT_ACK', { seq: this.badSeq ? seq + 1 : seq });
      }
      case 'FENCE': this.state = 'FENCED'; if (this.runId) this.runClosed = true; return ok('FENCED', {});
      case 'REPORT': return ok('REPORT', { counters: {}, measurements: [], same_source_observed: null, origin_counts_available: false, worker_verification_attempts: [] });
      default: return this.#reply(req, false, 'ILLEGAL_STATE', {});
    }
  }
  #reply(req: Json, ok: boolean, result: string, data: Json): Json {
    const reply = { version: 1, request_id: req['request_id'], state: this.state, run_id: this.runId, config_digest: this.digest, incarnation: this.incarnation, ok, result, data };
    validateControlResponse(reply);
    return reply;
  }
}

export class FakeRedis implements RedisPort {
  calls: string[] = [];
  failPrepare = false; failInstall = false;
  runStart = Date.now();
  async prepare(runId: string) {
    this.calls.push(`prepare:${runId}`);
    if (this.failPrepare) throw new Error('redis down');
    return { run_start_ms: this.runStart, snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40) };
  }
  async install(manifest: Manifest, digest: string) {
    this.calls.push(`install:${manifest.run_id}:${digest}`);
    if (this.failInstall) throw new Error('acl failure');
    return { username: 'gateway', password: 'not-a-real-password' };
  }
}

/** Fences every link with the emergency FENCE and requires the strong acknowledgement; discard only after that. */
export class FakeReset implements ResetPort {
  events: string[] = [];
  failFence = false; failDiscard = false;
  readonly #links: RoleLink[];
  readonly #issued = new WeakSet<object>();
  constructor(links: RoleLink[]) { this.#links = links; }
  async fenceAll() {
    this.events.push('fence-start');
    const replies = await Promise.all(this.#links.map(async (l) => {
      try { return await l.send(emergencyFence('operator-stop'), 4000); } catch { return null; }
    }));
    if (this.failFence || replies.some((r) => !r || r['ok'] !== true || r['result'] !== 'FENCED' || r['state'] !== 'FENCED')) throw new Error('unconfirmed');
    this.events.push('fence-confirmed');
    const receipt = Object.freeze({}); this.#issued.add(receipt); return receipt;
  }
  async discardOldRedis(receipt: unknown) {
    if (typeof receipt !== 'object' || !receipt || !this.#issued.has(receipt)) throw new Error('bad receipt');
    this.events.push('redis-discarded');
    if (this.failDiscard) throw new Error('unconfirmed');
  }
}

/** New links onto the SAME role objects (a replacement controller attaching to roles a previous run used). */
export function relink(rig: ControllerRig): { links: RunLinks; log: LogEntry[] } {
  const log: LogEntry[] = [];
  const wrap = (role: RoleName, handle: (raw: unknown) => Promise<Json>) => new LoggedLink(new InProcessLink(role, handle), log);
  return { log, links: {
    issuer: wrap('issuer', (r) => rig.issuer.handle(r)), origin: wrap('origin', (r) => rig.origin.handle(r)),
    clients: Object.fromEntries(CLIENT_IDS.map((id) => [id, wrap(`client-${id}`, (r) => rig.clients[id].handle(r))])) as unknown as Record<ClientId, RoleLink>,
    gateway: wrap('gateway', (r) => rig.gateway.handle(r)),
  } };
}

export type ControllerRig = {
  launcher: { launched: number; fail: boolean; launch: (input: { redis: { username: string; password: string } }) => Promise<void> };
  links: RunLinks; log: LogEntry[]; gateway: FakeGateway; redis: FakeRedis; reset: FakeReset;
  issuer: IssuerRole; origin: OriginRole; clients: Record<ClientId, ClientRole>; all: RoleLink[]; stop: () => Promise<void>;
};

export function controllerRig(options: { gateway?: boolean } = {}): ControllerRig {
  const pki = createPki();
  const tls = pki.leaf(PROTOCOL.issuer_name);
  const files: Record<string, string> = { '/run/secrets/tls.crt': tls.cert, '/run/secrets/tls.key': tls.key, '/run/secrets/ca.crt': pki.caPem };
  const readSecret = (p: string) => { const v = files[p]; if (v === undefined) throw new Error('missing'); return Buffer.from(v); };
  const log: LogEntry[] = [];
  const issuer = new IssuerRole({ readSecret, listen: { host: '127.0.0.1', port: 0 }, clock: () => performance.now(), drainMs: 500 });
  const origin = new OriginRole({ listen: { host: '127.0.0.1', port: 0 }, drainMs: 500 });
  const clients = Object.fromEntries(CLIENT_IDS.map((id) => [id, new ClientRole({ readSecret, proxy: { host: '127.0.0.1', port: 9 }, drainMs: 500 })])) as Record<ClientId, ClientRole>;
  const gateway = new FakeGateway();
  const wrap = (role: RoleName, handle: (raw: unknown) => Promise<Json>) => new LoggedLink(new InProcessLink(role, handle), log);
  const links: RunLinks = {
    issuer: wrap('issuer', (r) => issuer.handle(r)),
    origin: wrap('origin', (r) => origin.handle(r)),
    clients: Object.fromEntries(CLIENT_IDS.map((id) => [id, wrap(`client-${id}`, (r) => clients[id].handle(r))])) as unknown as Record<ClientId, RoleLink>,
    ...(options.gateway === false ? {} : { gateway: wrap('gateway', (r) => gateway.handle(r)) }),
  };
  const all = [links.issuer, links.origin, ...CLIENT_IDS.map((id) => links.clients[id]), ...(links.gateway ? [links.gateway] : [])];
  // The barrier fakes talk to the roles through their own, unlogged links so ordering assertions see only controller traffic.
  const raw: RoleLink[] = [new InProcessLink('issuer', (r) => issuer.handle(r)), new InProcessLink('origin', (r) => origin.handle(r)),
    ...CLIENT_IDS.map((id) => new InProcessLink(`client-${id}` as RoleName, (r) => clients[id].handle(r))),
    ...(links.gateway ? [new InProcessLink('gateway', (r) => gateway.handle(r))] : [])];
  const reset = new FakeReset(raw);
  const launcher = { launched: 0, fail: false, async launch(input: { redis: { username: string; password: string } }) { if (launcher.fail || !input.redis.password) throw new Error('launch'); launcher.launched += 1; } };
  return { launcher, links, log, gateway, redis: new FakeRedis(), reset, issuer, origin, clients, all, stop: async () => { await reset.fenceAll().catch(() => undefined); } };
}
