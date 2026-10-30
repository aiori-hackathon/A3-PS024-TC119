// Controller access to the replay store. Redis is on an internal network, so the controller reaches it only through
// `docker exec` into the exact Redis container, over its private local socket, as the controller account. Every command is
// sent on STDIN: the Lua sources and the gateway's new ACL password never appear in argv, and the controller's own
// password reaches redis-cli through an environment variable that docker forwards by NAME (the value is in this process's
// environment, not in any command line). The bootstrap itself is the shared public artifact; nothing is re-derived here.
import { randomBytes } from 'node:crypto';
import { configurationDigest, type Manifest } from '../../../../contracts/lib/index.ts';
import {
  initializeStore, installGatewayAcl, loadReplayScripts, readRunStart, verifyStoreReady, REPLAY_SCRIPTS, type RedisIo,
} from '../../../../contracts/lib/replay.ts';
import type { DockerCli } from './docker.ts';
import type { GatewayCredentials, RedisPort } from './ports.ts';

const SOCKET = '/run/redis/redis.sock';
export const GATEWAY_REDIS_USER = 'gateway';

/** Quoting understood by redis-cli's line parser: double-quoted, backslash escapes, every non-printable byte as \xHH. */
export function quoteForRedisCli(arg: string | number): string {
  const bytes = Buffer.from(String(arg), 'utf8');
  let out = '"';
  for (const b of bytes) {
    if (b === 0x5c) out += '\\\\';
    else if (b === 0x22) out += '\\"';
    else if (b === 0x0a) out += '\\n';
    else if (b === 0x0d) out += '\\r';
    else if (b === 0x09) out += '\\t';
    else if (b < 0x20 || b > 0x7e) out += '\\x' + b.toString(16).padStart(2, '0');
    else out += String.fromCharCode(b);
  }
  return out + '"';
}

export class DockerRedisIo implements RedisIo {
  readonly #cli: DockerCli;
  readonly #redisId: string;
  readonly #password: string;
  readonly #timeoutMs: number;
  constructor(cli: DockerCli, redisContainerId: string, controllerPassword: string, timeoutMs = 20_000) {
    this.#cli = cli; this.#redisId = redisContainerId; this.#password = controllerPassword; this.#timeoutMs = timeoutMs;
  }
  async call(command: string, ...args: (string | number)[]): Promise<unknown> {
    const line = [command, ...args].map(quoteForRedisCli).join(' ') + '\n';
    const r = await this.#cli.run(
      ['exec', '-i', '-e', 'REDISCLI_AUTH', this.#redisId, 'redis-cli', '-s', SOCKET, '--user', 'controller', '--no-auth-warning', '--json'],
      { input: line, timeoutMs: this.#timeoutMs, env: { ...process.env, REDISCLI_AUTH: this.#password } });
    const out = r.stdout.trim();
    if (r.timedOut || r.failed || r.status !== 0 || out === '' || /^(\(error\)|error:)/i.test(out)) throw new Error('redis-call-failed');
    try { return JSON.parse(out); } catch { throw new Error('redis-call-failed'); }
  }
}

/** Real replay-store bootstrap using the shared artifact, with a freshly generated gateway password per run. */
export class DockerRedis implements RedisPort {
  readonly #io: RedisIo;
  readonly #newPassword: () => string;
  readonly #startOffsetMs: number;
  /**
   * `startOffsetMs` moves run_start_ms into the past (never the future) so an epoch boundary arrives soon after start; it is
   * used only by the epoch-boundary run. It is still derived from this Redis instance's TIME.
   */
  constructor(io: RedisIo, newPassword: () => string = () => randomBytes(36).toString('base64url'), startOffsetMs = 0) {
    if (!Number.isSafeInteger(startOffsetMs) || startOffsetMs < 0) throw new Error('offset');
    this.#io = io; this.#newPassword = newPassword; this.#startOffsetMs = startOffsetMs;
  }

  async prepare(_runId: string) {
    await loadReplayScripts(this.#io);
    const now = await readRunStart(this.#io); // this exact Redis instance's TIME, never the host clock
    const run_start_ms = now - this.#startOffsetMs;
    if (run_start_ms < 1) throw new Error('offset');
    return { run_start_ms, snapshot_script_sha1: REPLAY_SCRIPTS.snapshot.sha1, claim_script_sha1: REPLAY_SCRIPTS.claim.sha1 };
  }

  async install(manifest: Manifest, digest: string): Promise<GatewayCredentials> {
    if (configurationDigest(manifest) !== digest) throw new Error('digest-mismatch');
    const password = this.#newPassword();
    await initializeStore(this.#io, manifest);
    await installGatewayAcl(this.#io, GATEWAY_REDIS_USER, password);
    await verifyStoreReady(this.#io, manifest, GATEWAY_REDIS_USER); // field-by-field, before anything is enabled
    return Object.freeze({ username: GATEWAY_REDIS_USER, password });
  }
}
