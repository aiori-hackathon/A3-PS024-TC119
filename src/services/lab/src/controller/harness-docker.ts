// Docker-backed security harness and fault injection. Both act on exact container IDs; neither prints anything.
//  * DockerHarness runs the one-shot harness process inside a client container. Credentials return to controller memory on a
//    private pipe (the documented quarantined-fixture exception) and are never logged or written.
//  * DockerFaults applies REAL faults to the live deployment: a script flush, deleted/corrupted guards, a regressed highwater
//    or a stopped Redis, and a paused origin. Nothing is simulated or selected by an environment flag; these are reachable
//    only from the allowlisted orchestrated scenarios.
import { decodeBase64Url, PROTOCOL, type Manifest } from '../../../../contracts/lib/index.ts';
import { loadReplayScripts, readRunStart, type RedisIo } from '../../../../contracts/lib/replay.ts';
import type { DockerCli, DockerProject, Instance } from './docker.ts';
import type { ClientId, FaultPort, HarnessPort, RedisFault } from './ports.ts';
import { encodeBase64Url } from '../../../../contracts/lib/index.ts';

export class DockerHarness implements HarnessPort {
  readonly #cli: DockerCli;
  readonly #clients: Map<ClientId, Instance>;
  constructor(cli: DockerCli, clients: Map<ClientId, Instance>) { this.#cli = cli; this.#clients = clients; }

  async #run(client: ClientId, payload: object): Promise<Record<string, unknown>> {
    const inst = this.#clients.get(client);
    if (!inst) throw new Error('harness-unavailable');
    const r = await this.#cli.run(['exec', '-i', inst.container_id, 'node', 'dist/harness.mjs'], { input: JSON.stringify(payload), timeoutMs: 120_000 });
    if (r.timedOut || r.failed || r.status !== 0) throw new Error('harness-failed');
    try { const out = JSON.parse(r.stdout.trim()) as Record<string, unknown>; if (out['error']) throw new Error('x'); return out; } catch { throw new Error('harness-failed'); }
  }
  async issue(client: ClientId, manifest: Manifest, vouchers: string[]): Promise<Uint8Array[]> {
    const out = await this.#run(client, { op: 'issue', manifest, vouchers });
    const tokens = out['tokens'];
    if (!Array.isArray(tokens) || tokens.length !== vouchers.length) throw new Error('harness-failed');
    return tokens.map((t) => decodeBase64Url(String(t), PROTOCOL.token_bytes));
  }
  async present(client: ClientId, manifest: Manifest, tokens: Uint8Array[]): Promise<{ status: number; label: string | null }[]> {
    const out = await this.#run(client, { op: 'present', manifest, tokens: tokens.map((t) => encodeBase64Url(t)) });
    const results = out['results'];
    if (!Array.isArray(results) || results.length !== tokens.length) throw new Error('harness-failed');
    return results.map((r: { status: number; label: string | null }) => ({ status: Number(r.status), label: typeof r.label === 'string' ? r.label : null }));
  }
}

export class DockerFaults implements FaultPort {
  readonly #io: RedisIo;
  readonly #project: DockerProject;
  readonly #redisId: string;
  readonly #originId: string;
  constructor(io: RedisIo, project: DockerProject, redisId: string, originId: string) { this.#io = io; this.#project = project; this.#redisId = redisId; this.#originId = originId; }

  async redis(kind: RedisFault): Promise<void> {
    const io = this.#io;
    switch (kind) {
      case 'script-flush': await io.call('SCRIPT', 'FLUSH'); return;
      case 'clock-delete': await io.call('DEL', 'pp:clock'); return;
      case 'policy-corrupt': await io.call('HSET', 'pp:policy', 'guard_ms', '1'); return;
      // A recorded highwater AHEAD of the store's own clock is exactly what a backward clock step looks like to the scripts.
      case 'clock-regress': await io.call('HSET', 'pp:clock', 'last_now_ms', String((await readRunStart(io)) + 400_000)); return;
      case 'redis-stop': await this.#project.stop(this.#redisId); return;
    }
  }
  async reloadScripts(): Promise<void> { await loadReplayScripts(this.#io); }
  async pauseOrigin(): Promise<void> { await this.#project.pause(this.#originId); }
  async unpauseOrigin(): Promise<void> { await this.#project.unpause(this.#originId); }
}
