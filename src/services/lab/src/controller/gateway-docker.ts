// Starts the gateway's serving entry point inside its (idle, fenced) container with the private startup input the gateway
// documents (`docs/implementation/GATEWAY_RUNTIME.md`): one JSON object on stdin, then the stream is closed.
//   { listen_host, tls: { key, cert }, redis: { username, password } }
// The input is never placed in argv, environment, container labels or logs. The gateway creates its control socket only
// after it has validated that input, so the control link is opened afterwards by retrying until the socket exists.
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { ChildProcess } from 'node:child_process';
import type { DockerCli, Instance } from './docker.ts';
import { HelperLink } from './link.ts';
import { discovery } from './envelope.ts';
import type { GatewayCredentials, GatewayLauncher, RoleLink } from './ports.ts';

/** The gateway's frontend interface on proxy_gateway (infra/compose.yaml). A concrete address: wildcards are refused. */
export const GATEWAY_LISTEN_HOST = '172.28.30.10';
export const MAX_STARTUP_INPUT = 131072;

export type GatewayLauncherOptions = { secretsDir: string; listenHost?: string; attempts?: number; retryMs?: number };

export class DockerGatewayLauncher implements GatewayLauncher {
  readonly #cli: DockerCli;
  readonly #instance: Instance;
  readonly #opts: Required<GatewayLauncherOptions>;
  #server: ChildProcess | null = null;
  constructor(cli: DockerCli, instance: Instance, options: GatewayLauncherOptions) {
    this.#cli = cli; this.#instance = instance;
    this.#opts = { listenHost: GATEWAY_LISTEN_HOST, attempts: 60, retryMs: 250, ...options };
  }

  async launch(input: { redis: GatewayCredentials }): Promise<RoleLink> {
    if (this.#server) throw new Error('already-launched'); // one launch per container; no same-run restart
    const [key, cert] = await Promise.all([readFile(join(this.#opts.secretsDir, 'gateway', 'tls.key'), 'utf8'), readFile(join(this.#opts.secretsDir, 'gateway', 'tls.crt'), 'utf8')]);
    const payload = JSON.stringify({ listen_host: this.#opts.listenHost, tls: { key, cert }, redis: { username: input.redis.username, password: input.redis.password } });
    if (Buffer.byteLength(payload, 'utf8') > MAX_STARTUP_INPUT) throw new Error('startup-input-too-large');
    // `docker exec -i`: stdin only. No -e, no secrets in the argument list.
    const server = this.#cli.spawn(['exec', '-i', this.#instance.container_id, 'node', '/app/dist/serve.mjs']);
    this.#server = server;
    let exited = false;
    server.on('close', () => { exited = true; });
    server.on('error', () => { exited = true; });
    server.stdout?.resume(); server.stderr?.resume(); // discarded: never log gateway output
    server.stdin!.on('error', () => undefined);
    server.stdin!.end(payload);
    for (let i = 0; i < this.#opts.attempts; i++) {
      if (exited) break;
      const link = new HelperLink(this.#instance.role, this.#cli.spawn(['exec', '-i', this.#instance.container_id, 'node', '/app/dist/control-helper.mjs']));
      try { const r = await link.send(discovery(), 2000); if (r['ok'] === true) return link; } catch { /* socket not there yet */ }
      link.close();
      await new Promise((r) => setTimeout(r, this.#opts.retryMs));
    }
    this.stop();
    throw new Error('gateway-control-unavailable');
  }

  /** Terminates the serving client. Process-tree exit is confirmed by container-level termination, not by this. */
  stop(): void { try { this.#server?.kill(); } catch { /* already gone */ } }
}
