// Docker-backed pieces of the controller: immutable container identity, control links through `docker exec` (pinned to
// the container ID, never a reusable service name), kill-and-confirm termination, Redis discard, exit monitoring.
//
// Two rules shape this file:
//  1. NOTHING here blocks the event loop. Every Docker call is asynchronous with a monotonic deadline, because the
//     controller must keep sending heartbeats while it supervises or shuts down (a blocked loop silently lets leases
//     lapse and prevents AbortSignal deadlines from firing).
//  2. UNKNOWN IS NOT GONE. An instance's state is one of running / stopped / absent / unknown. Only an explicit
//     inspection of the exact immutable ID, answering "stopped" or the daemon's authoritative "no such object", counts as
//     exit evidence. A daemon error, permission failure, timeout or malformed answer is `unknown` and never confirms
//     anything, so it can never lead to a Redis discard.
// The Docker CLI sits behind a small interface so every obligation is unit-tested without a daemon.
import { spawn, type ChildProcess } from 'node:child_process';
import { CLIENT_IDS, type Json, type OriginCounts, type RoleLink, type RoleName } from './ports.ts';
import { HelperLink } from './link.ts';

export type RunResult = { status: number | null; stdout: string; stderr: string; timedOut: boolean; failed: boolean };
export type RunOptions = { timeoutMs?: number; input?: string; env?: NodeJS.ProcessEnv; signal?: AbortSignal };
export interface DockerCli {
  run(args: string[], options?: RunOptions): Promise<RunResult>;
  spawn(args: string[], env?: NodeJS.ProcessEnv): ChildProcess;
}

const MAX_OUTPUT = 8 * 1024 * 1024;
export const realDocker: DockerCli = {
  run: (args, options = {}) => new Promise((resolve) => {
    const child = spawn('docker', args, { stdio: ['pipe', 'pipe', 'pipe'], shell: false, ...(options.env ? { env: options.env } : {}) });
    let stdout = '', stderr = '', timedOut = false, settled = false;
    const done = (status: number | null, failed: boolean) => {
      if (settled) return; settled = true; clearTimeout(timer); options.signal?.removeEventListener('abort', abort);
      resolve({ status, stdout, stderr, timedOut, failed });
    };
    const abort = () => { child.kill(); done(null, true); };
    const timer = setTimeout(() => { timedOut = true; child.kill(); done(null, true); }, options.timeoutMs ?? 60_000);
    if (options.signal?.aborted) { abort(); return; }
    options.signal?.addEventListener('abort', abort, { once: true });
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stdout.on('data', (d: string) => { if (stdout.length < MAX_OUTPUT) stdout += d; });
    child.stderr.on('data', (d: string) => { if (stderr.length < MAX_OUTPUT) stderr += d; });
    child.on('error', () => done(null, true));
    child.on('close', (code) => done(code, false));
    child.stdin.on('error', () => undefined);
    child.stdin.end(options.input ?? '');
  }),
  spawn: (args, env) => spawn('docker', args, { stdio: ['pipe', 'pipe', 'pipe'], shell: false, ...(env ? { env } : {}) }),
};

export const SERVICE_FOR_ROLE: Record<RoleName, string> = {
  gateway: 'gateway', issuer: 'issuer', origin: 'protected-origin',
  'client-A': 'client-a', 'client-B': 'client-b', 'client-C': 'client-c', 'client-D': 'client-d', 'client-E': 'client-e',
};
export const ROLE_NAMES = Object.keys(SERVICE_FOR_ROLE) as RoleName[];
const CONTAINER_ID = /^[0-9a-f]{64}$/;
const HELPER = ['node', 'dist/control-helper.mjs'] as const;

export type Instance = { role: RoleName; container_id: string };
/** `unknown` is a first-class answer: it blocks reset and discard. */
export type InstanceState = 'running' | 'stopped' | 'absent' | 'unknown';

export class DockerProject {
  readonly #cli: DockerCli;
  readonly #composeFile: string;
  constructor(cli: DockerCli, composeFile: string) { this.#cli = cli; this.#composeFile = composeFile; }

  compose(args: string[], options?: RunOptions): Promise<RunResult> { return this.#cli.run(['compose', '-f', this.#composeFile, ...args], options); }

  async #idFor(service: string): Promise<string> {
    const q = await this.compose(['ps', '-q', '-a', service], { timeoutMs: 20_000 });
    const ids = q.stdout.trim().split('\n').filter(Boolean);
    if (q.status !== 0 || ids.length !== 1) throw new Error('instance-unavailable');
    const inspected = await this.#cli.run(['inspect', '--format', '{{.Id}}', ids[0]!], { timeoutMs: 10_000 });
    const full = inspected.stdout.trim();
    if (inspected.status !== 0 || !CONTAINER_ID.test(full)) throw new Error('instance-unavailable');
    return full;
  }
  /** Immutable 64-hex container ID for a role right now. A service name is never used as identity after this. */
  async instance(role: RoleName): Promise<Instance> { return { role, container_id: await this.#idFor(SERVICE_FOR_ROLE[role]) }; }
  async redisInstance(): Promise<string> { return this.#idFor('redis'); }
  /** All containers (running or not) the project currently has, for the old-generation check before any recreate. */
  async existing(): Promise<{ service: string; container_id: string }[]> {
    const out: { service: string; container_id: string }[] = [];
    for (const service of [...Object.values(SERVICE_FOR_ROLE), 'redis', 'proxy']) {
      const q = await this.compose(['ps', '-q', '-a', service], { timeoutMs: 20_000 });
      if (q.status !== 0) throw new Error('instance-unavailable'); // cannot enumerate: do not assume the project is empty
      for (const id of q.stdout.trim().split('\n').filter(Boolean)) {
        const full = (await this.#cli.run(['inspect', '--format', '{{.Id}}', id], { timeoutMs: 10_000 })).stdout.trim();
        if (!CONTAINER_ID.test(full)) throw new Error('instance-unavailable');
        out.push({ service, container_id: full });
      }
    }
    return out;
  }

  /** Inspects the exact ID. Anything other than a well-formed answer for THAT ID, or the daemon's explicit absence, is unknown. */
  async state(containerId: string, signal?: AbortSignal): Promise<InstanceState> {
    if (!CONTAINER_ID.test(containerId)) return 'unknown';
    const r = await this.#cli.run(['inspect', '--format', '{{.Id}} {{.State.Running}} {{.State.Status}}', containerId], { timeoutMs: 5_000, ...(signal ? { signal } : {}) });
    if (r.timedOut || r.failed) return 'unknown';
    if (r.status === 0) {
      const m = /^([0-9a-f]{64}) (true|false) (created|running|paused|restarting|removing|exited|dead)\r?\n?$/.exec(r.stdout);
      if (!m || m[1] !== containerId) return 'unknown'; // an answer about some other object proves nothing
      if (m[2] === 'true' || m[3] === 'paused' || m[3] === 'restarting' || m[3] === 'removing') return 'running';
      return 'stopped';
    }
    // Absence only on the daemon's explicit statement naming this exact ID. Permission errors, daemon-down messages,
    // empty output and anything else stay unknown.
    return r.status === 1 && new RegExp(`No such (object|container): ${containerId}\\s*$`).test(r.stderr.trim()) ? 'absent' : 'unknown';
  }
  /** Opens a persistent control link inside exactly this container. stdin stays open for the whole run. */
  openLink(instance: Instance): RoleLink {
    return new HelperLink(instance.role, this.#cli.spawn(['exec', '-i', instance.container_id, ...HELPER]));
  }
  async kill(containerId: string, signal?: AbortSignal): Promise<void> { await this.#cli.run(['kill', containerId], { timeoutMs: 15_000, ...(signal ? { signal } : {}) }); }
  async remove(containerId: string, signal?: AbortSignal): Promise<void> { await this.#cli.run(['rm', '-f', containerId], { timeoutMs: 30_000, ...(signal ? { signal } : {}) }); }

  /**
   * Watches container exits. `onExit` receives the role whose pinned container died, was killed or went OOM.
   * Returns a stop function. Event-stream loss is itself unsafe, so it reports every role as lost.
   */
  watch(instances: readonly Instance[], onExit: (role: RoleName) => void): () => void {
    const byId = new Map(instances.map((i) => [i.container_id, i.role]));
    const child = this.#cli.spawn(['events', '--format', '{{json .}}', '--filter', 'type=container', '--filter', 'event=die', '--filter', 'event=kill',
      '--filter', 'event=oom', '--filter', 'event=stop', '--filter', 'event=destroy']);
    let stopped = false, buffer = '';
    child.stdout!.setEncoding('utf8');
    child.stdout!.on('data', (d: string) => {
      buffer += d; let i: number;
      while ((i = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, i); buffer = buffer.slice(i + 1);
        try {
          // Docker versions differ: the container ID is top-level `id` in older formats and `Actor.ID` in current ones.
          const ev = JSON.parse(line) as { id?: string; Actor?: { ID?: string } };
          const role = byId.get(ev.Actor?.ID ?? ev.id ?? '');
          if (role) onExit(role);
        } catch { /* ignore unrelated frames */ }
      }
    });
    child.stderr?.resume();
    child.on('close', () => { if (!stopped) for (const role of byId.values()) onExit(role); });
    return () => { stopped = true; child.kill(); };
  }
}

export type Target = Readonly<{ role: RoleName; incarnation: string; instance_id: string }>;
const now = () => performance.now();

export type AdapterOptions = { sleep?: (ms: number) => Promise<void>; controlTimeoutMs?: number; confirmMs?: number; killRetryMs?: number };

/**
 * The four adapter functions Krish's ResetBarrier (and the partial barrier) call. Each acts on the exact old container
 * ID. A schema-valid FENCED reply is returned as-is for the caller to bind to the old identity; termination is
 * kill-and-confirm by inspection of the exact ID, never the success of the kill call itself. Deadlines are monotonic and
 * rechecked after every await; nothing is returned once the caller's signal has aborted.
 */
export class DockerAdapters {
  readonly #project: DockerProject;
  readonly #links: Map<RoleName, RoleLink>;
  readonly #sleep: (ms: number) => Promise<void>;
  readonly #controlMs: number;
  readonly #confirmMs: number;
  readonly #killRetryMs: number;
  /** Settled origin counters seen in the strong REPORT, retained as the only origin evidence. */
  originCounts: OriginCounts | null = null;
  constructor(project: DockerProject, links: Map<RoleName, RoleLink>, options: AdapterOptions = {}) {
    this.#project = project; this.#links = links;
    this.#sleep = options.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.#controlMs = options.controlTimeoutMs ?? 10_000;
    this.#confirmMs = options.confirmMs ?? 9_000;
    this.#killRetryMs = options.killRetryMs ?? 2_000;
  }

  async fence(target: Target, request: Readonly<Json>, signal: AbortSignal): Promise<unknown> {
    const link = this.#links.get(target.role);
    if (!link || signal.aborted) throw new Error('no-link');
    const started = now();
    const reply = await link.send({ ...request }, this.#controlMs);
    if (signal.aborted || now() - started > this.#controlMs) throw new Error('late-reply'); // a reply after the deadline is not accepted
    return reply;
  }

  /** Kill, then poll the exact ID. Only `stopped` or authoritative `absent` is evidence; running and unknown keep waiting. */
  async terminate(target: Target, signal: AbortSignal): Promise<unknown> {
    const deadline = now() + this.#confirmMs;
    let lastKill = -Infinity;
    while (now() < deadline && !signal.aborted) {
      if (now() - lastKill >= this.#killRetryMs) { lastKill = now(); await this.#project.kill(target.instance_id, signal); }
      const state = await this.#project.state(target.instance_id, signal);
      if (signal.aborted || now() >= deadline) break;
      if (state === 'stopped' || state === 'absent') {
        // The container's PID namespace dies with it, so confirmed exit of the container is confirmed exit of its tree.
        return { role: target.role, incarnation: target.incarnation, instance_id: target.instance_id, exited: true, descendants_exited: true };
      }
      await this.#sleep(100);
    }
    throw new Error('exit-unconfirmed');
  }

  async reportOrigin(target: Target, request: Readonly<Json>, signal: AbortSignal): Promise<unknown> {
    const link = this.#links.get(target.role);
    if (!link || signal.aborted) throw new Error('no-link');
    const started = now();
    const reply = await link.send({ ...request }, this.#controlMs);
    if (signal.aborted || now() - started > this.#controlMs) throw new Error('late-reply');
    const c = reply['data']?.counters;
    if (reply['ok'] === true && reply['data']?.origin_counts_available === true && c) {
      this.originCounts = Object.freeze({ protected_requests_received: c.protected_requests_received, generation_mismatches: c.generation_mismatches, resources_served: c.resources_served });
    }
    return reply;
  }

  /** Remove the exact old Redis container and require the daemon's explicit statement that it no longer exists. */
  async discardRedis(instanceId: string, signal: AbortSignal): Promise<unknown> {
    const deadline = now() + this.#confirmMs;
    let lastRemove = -Infinity;
    while (now() < deadline && !signal.aborted) {
      if (now() - lastRemove >= this.#killRetryMs) { lastRemove = now(); await this.#project.remove(instanceId, signal); }
      const state = await this.#project.state(instanceId, signal);
      if (signal.aborted || now() >= deadline) break;
      if (state === 'absent') return { instance_id: instanceId, exited: true }; // gone entirely: process and its memory-only state discarded
      await this.#sleep(100); // running, stopped-but-present and unknown are all "not yet discarded"
    }
    throw new Error('discard-unconfirmed');
  }
}

export const clientRoles: RoleName[] = CLIENT_IDS.map((c) => `client-${c}` as RoleName);
