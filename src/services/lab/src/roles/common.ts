// Shared process wiring for role entry points. Configuration comes from a few fixed environment names that carry no
// secrets (socket path, secrets directory, bind address); credentials only ever arrive through the control channel.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PROTOCOL } from '../../../../contracts/lib/index.ts';

export const controlSocketPath = (): string => process.env['PS024_CONTROL_SOCKET'] ?? PROTOCOL.control_socket;

/** Maps a manifest-validated /run/secrets/<name> path into the (test-overridable) secrets directory. */
export function readSecret(path: string): Buffer {
  const m = /^\/run\/secrets\/([A-Za-z0-9_.-]+)$/.exec(path);
  if (!m) throw new Error('secret-path');
  return readFileSync(join(process.env['PS024_SECRETS_DIR'] ?? '/run/secrets', m[1]!));
}

/** Unspecified binds are refused by default: Compose must name the interface. */
export function listenConfig(): { host: string; port: number } {
  const port = Number(process.env['PS024_LISTEN_PORT'] ?? 443);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('listen-port');
  return { host: process.env['PS024_BIND_ADDRESS'] ?? '127.0.0.1', port };
}

/** Run `fence` on SIGTERM/SIGINT so a stop request still takes the strong-barrier path before exit. */
export function exitOnSignal(fence: () => Promise<unknown>): void {
  const stop = () => { void fence().finally(() => process.exit(0)); };
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
}

export const fenceRequest = () => ({
  version: 1, request_id: '0'.repeat(32), command: 'FENCE', run_id: null, config_digest: null, target_incarnation: null, payload: { reason: 'operator-stop' },
});
