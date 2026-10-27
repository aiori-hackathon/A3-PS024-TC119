import { randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import { WorkerHost } from './worker-host.ts';
import type { WorkerCloseReason, WorkerLeaseGrant } from './worker-lease.ts';
import type { RedisEndpoint } from './redis-adapter.ts';
import type { GatewayTls } from './https-gateway.ts';

const incarnation = randomBytes(16).toString('hex');
let host: WorkerHost | null = null, busy = false, stopping = false, listenHost = '', listenPort = 443;
function send(value: unknown): void {
  try { if (!process.send?.(value, error => { if (error) process.exit(1); })) process.exit(1); }
  catch { process.exit(1); }
}
function fault(reason: WorkerCloseReason): void {
  if (stopping) return; stopping = true;
  send({ kind: 'fault', reason });
  const timer = setTimeout(() => process.exit(1), 1000); timer.unref();
  void host?.close().finally(() => process.exit(1));
}
process.on('disconnect', () => process.exit(1)); // Parent death must not leave an orphan serving process.
process.on('uncaughtException', () => fault('unsafe-state'));
process.on('unhandledRejection', () => fault('unsafe-state'));
process.on('SIGTERM', () => fault('operator-stop'));
process.on('message', (raw: unknown) => {
  const run = async () => {
    const message = raw as Record<string, unknown>;
    if (!message || typeof message !== 'object' || Array.isArray(message) ||
      typeof message['id'] !== 'string' || !/^[0-9a-f]{32}$/.test(message['id']) ||
      typeof message['command'] !== 'string' || Buffer.byteLength(JSON.stringify(raw)) > 131072) throw Error();
    const id = message['id'];
    if (message['command'] === 'STOP') {
      stopping = true;
      const timer = setTimeout(() => process.exit(1), 1000); timer.unref();
      if (host) await host.close();
      send({ kind: 'reply', id, ok: true }); process.exit(0);
    }
    if (busy || stopping) throw Error(); busy = true;
    try {
      if (message['command'] === 'PREPARE') {
        if (host) throw Error();
        const config = message['configuration'] as { endpoint: RedisEndpoint; tls: GatewayTls; listen_host: string; listen_port: number };
        if (!config || !isIP(config.listen_host) || !Number.isInteger(config.listen_port) || config.listen_port < 1 || config.listen_port > 65535 ||
          typeof message['supervisor'] !== 'string') throw Error();
        listenHost = config.listen_host; listenPort = config.listen_port;
        host = WorkerHost.prepare(message['manifest'], incarnation, message['supervisor'], config.endpoint, config.tls, fault);
        await host.ready();
      } else if (!host) throw Error();
      else if (message['command'] === 'ENABLE') { if (!host.enable(message['grant'] as WorkerLeaseGrant)) throw Error(); }
      else if (message['command'] === 'HEARTBEAT') { if (!host.heartbeat(message['grant'] as WorkerLeaseGrant)) throw Error(); }
      else if (message['command'] === 'LISTEN') await host.listen(listenHost, listenPort);
      else if (message['command'] === 'REPORT') {
        send({ kind: 'reply', id, ok: true, attempts: host.attempts }); return;
      } else throw Error();
      if (stopping) return;
      send({ kind: 'reply', id, ok: true });
    } finally { busy = false; }
  };
  void run().catch(() => fault('unsafe-state'));
});
send({ kind: 'hello', incarnation, stamp: String(process.hrtime.bigint()) });
