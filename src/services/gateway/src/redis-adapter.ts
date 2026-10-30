import { Redis } from 'ioredis';
import { ContractError, validateManifest } from '../../../contracts/lib/index.ts';
import { ReplayStore, type ReplayConnection, type ReplayFault } from './replay-store.ts';

/** Private deployment configuration, never request data. No URL/arbitrary ioredis options. */
export type RedisEndpoint = { host: string; port: number; username: string; password: string };

class RedisConnection implements ReplayConnection {
  readonly #client: Redis;
  constructor(endpoint: RedisEndpoint, connectMs: number, commandMs: number) {
    this.#client = new Redis({ host: endpoint.host, port: endpoint.port, username: endpoint.username, password: endpoint.password,
      protocol: 2, db: 0, lazyConnect: true, enableReadyCheck: false, disableClientInfo: true,
      connectTimeout: connectMs, commandTimeout: commandMs, disconnectTimeout: 0,
      enableOfflineQueue: false, autoResendUnfulfilledCommands: false, autoResubscribe: false,
      maxRetriesPerRequest: 0, retryStrategy: () => null, reconnectOnError: () => false,
      enableAutoPipelining: false, showFriendlyErrorStack: false,
    });
  }
  async connect(): Promise<void> { await this.#client.connect(); }
  call(command: string, ...args: (string | number)[]): Promise<unknown> { return this.#client.call(command, ...args); }
  onLoss(handler: () => void): void {
    // Always install error listeners before lazy connect; never print raw client errors.
    this.#client.on('error', handler).on('close', handler).on('end', handler);
  }
  close(): void {
    try { this.#client.disconnect(false); }
    finally { this.#client.stream?.destroy(); }
  }
}

/** Fresh fenced initialization only. Reusing a closed run requires the full controller reset barrier. */
export async function openRedisReplayStore(configuration: unknown, endpoint: RedisEndpoint,
  onFault: (reason: ReplayFault) => void): Promise<ReplayStore> {
  let manifest;
  try {
    manifest = validateManifest(structuredClone(configuration));
    if (!endpoint || typeof endpoint.host !== 'string' || !/^[a-zA-Z0-9.:-]{1,253}$/.test(endpoint.host) ||
      !Number.isInteger(endpoint.port) || endpoint.port < 1 || endpoint.port > 65535 ||
      typeof endpoint.username !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(endpoint.username) ||
      typeof endpoint.password !== 'string' || endpoint.password.length < 1 || endpoint.password.length > 256) throw Error('endpoint');
  } catch { throw new ContractError('replay-configuration-invalid'); }
  const connections: ReplayConnection[] = [];
  try {
    for (let i = 0; i < manifest.limits.gateway.redis_connections_per_worker; i++) {
      connections.push(new RedisConnection(endpoint, manifest.limits.gateway.redis_connect_timeout_ms, manifest.limits.gateway.redis_command_timeout_ms));
    }
    return await ReplayStore.prepare(manifest, connections, onFault);
  } catch {
    for (const connection of connections) { try { connection.close(); } catch { /* close the remaining connections too */ } }
    throw new ContractError('replay-preparation-failed');
  }
}
