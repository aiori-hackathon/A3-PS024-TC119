// Docker-backed pieces of the controller: immutable container identity, control links through `docker exec` (pinned to
// the container ID, never a reusable service name), kill-and-confirm termination, Redis discard, exit monitoring.
// The Docker CLI sits behind a small interface so every obligation here is unit-tested without a daemon.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { CLIENT_IDS, type Json, type OriginCounts, type RoleLink, type RoleName } from './ports.ts';
import { HelperLink } from './link.ts';

export interface DockerCli {
  run(args: string[], timeoutMs?: number): { status: number | null; stdout: string; stderr: string };
  spawn(args: string[]): ChildProcess;
}
export const realDocker: DockerCli = {
  run: (args, timeoutMs = 60_000) => {
    const r = spawnSync('docker', args, { encoding: 'utf8', shell: false, timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 });
    return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
  },
  spawn: (args) => spawn('docker', args, { stdio: ['pipe', 'pipe', 'pipe'], shell: false }),
};

export const SERVICE_FOR_ROLE: Record<RoleName, string> = {
  gateway: 'gateway', issuer: 'issuer', origin: 'protected-origin',
  'client-A': 'client-a', 'client-B': 'client-b', 'client-C': 'client-c', 'client-D': 'client-d', 'client-E': 'client-e',
};
export const ROLE_NAMES = Object.keys(SERVICE_FOR_ROLE) as RoleName[];
const CONTAINER_ID = /^[0-9a-f]{64}$/;
const HELPER = ['node', 'dist/control-helper.mjs'] as const;

export type Instance = { role: RoleName; container_id: string };

export class DockerProject {
  readonly #cli: DockerCli;
  readonly #composeFile: string;
  constructor(cli: DockerCli, composeFile: string) { this.#cli = cli; this.#composeFile = composeFile; }

  compose(args: string[], timeoutMs?: number) { return this.#cli.run(['compose', '-f', this.#composeFile, ...args], timeoutMs); }

  /** Immutable 64-hex container ID for a role right now. A service name is never used as identity after this. */
  instance(role: RoleName): Instance {
    const q = this.compose(['ps', '-q', SERVICE_FOR_ROLE[role]]);
    const id = q.stdout.trim().split('\n')[0] ?? '';
    const full = id ? this.#cli.run(['inspect', '--format', '{{.Id}}', id]).stdout.trim() : '';
    if (q.status !== 0 || !CONTAINER_ID.test(full)) throw new Error('instance-unavailable');
    return { role, container_id: full };
  }
  redisInstance(): string {
    const q = this.compose(['ps', '-q', 'redis']);
    const full = q.stdout.trim() ? this.#cli.run(['inspect', '--format', '{{.Id}}', q.stdout.trim().split('\n')[0]!]).stdout.trim() : '';
    if (!CONTAINER_ID.test(full)) throw new Error('instance-unavailable');
    return full;
  }
  running(containerId: string): boolean | null {
    const r = this.#cli.run(['inspect', '--format', '{{.State.Running}}', containerId]);
    if (r.status !== 0) return null; // no such container
    return r.stdout.trim() === 'true';
  }
  /** Opens a persistent control link inside exactly this container. stdin stays open for the whole run. */
  openLink(instance: Instance): RoleLink {
    return new HelperLink(instance.role, this.#cli.spawn(['exec', '-i', instance.container_id, ...HELPER]));
  }
  kill(containerId: string): void { this.#cli.run(['kill', containerId], 15_000); }
  remove(containerId: string): void { this.#cli.run(['rm', '-f', containerId], 30_000); }

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

/**
 * The four adapter functions Krish's ResetBarrier (and the partial barrier below) call. Each acts on the exact old
 * container ID. A schema-valid FENCED reply is returned as-is for the caller to bind to the old identity; termination
 * is kill-and-confirm with `docker inspect`, never the success of the kill call itself.
 */
export class DockerAdapters {
  readonly #project: DockerProject;
  readonly #links: Map<RoleName, RoleLink>;
  readonly #sleep: (ms: number) => Promise<void>;
  readonly #controlMs: number;
  /** Settled origin counters seen in the strong REPORT, retained as the only origin evidence. */
  originCounts: OriginCounts | null = null;
  constructor(project: DockerProject, links: Map<RoleName, RoleLink>, options: { sleep?: (ms: number) => Promise<void>; controlTimeoutMs?: number } = {}) {
    this.#project = project; this.#links = links;
    this.#sleep = options.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.#controlMs = options.controlTimeoutMs ?? 10_000;
  }

  async fence(target: Target, request: Readonly<Json>, signal: AbortSignal): Promise<unknown> {
    const link = this.#links.get(target.role);
    if (!link || signal.aborted) throw new Error('no-link');
    return link.send({ ...request }, this.#controlMs);
  }

  async terminate(target: Target, signal: AbortSignal): Promise<unknown> {
    this.#project.kill(target.instance_id);
    for (let i = 0; i < 100 && !signal.aborted; i++) {
      const running = this.#project.running(target.instance_id);
      // Exited, or no longer present at all. A container's PID namespace dies with it, so its descendants are gone too.
      if (running === false || running === null) return { role: target.role, incarnation: target.incarnation, instance_id: target.instance_id, exited: true, descendants_exited: true };
      await this.#sleep(100);
    }
    throw new Error('exit-unconfirmed');
  }

  async reportOrigin(target: Target, request: Readonly<Json>, signal: AbortSignal): Promise<unknown> {
    const link = this.#links.get(target.role);
    if (!link || signal.aborted) throw new Error('no-link');
    const reply = await link.send({ ...request }, this.#controlMs);
    const c = reply['data']?.counters;
    if (reply['ok'] === true && reply['data']?.origin_counts_available === true && c) {
      this.originCounts = Object.freeze({ protected_requests_received: c.protected_requests_received, generation_mismatches: c.generation_mismatches, resources_served: c.resources_served });
    }
    return reply;
  }

  async discardRedis(instanceId: string, signal: AbortSignal): Promise<unknown> {
    if (signal.aborted) throw new Error('aborted');
    this.#project.remove(instanceId);
    for (let i = 0; i < 100 && !signal.aborted; i++) {
      const running = this.#project.running(instanceId);
      if (running === null) return { instance_id: instanceId, exited: true }; // gone entirely: process and memory-only state discarded
      await this.#sleep(100);
    }
    throw new Error('discard-unconfirmed');
  }
}

export const clientRoles: RoleName[] = CLIENT_IDS.map((c) => `client-${c}` as RoleName);
