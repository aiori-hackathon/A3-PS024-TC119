import { isIP } from 'node:net';
import { GatewaySupervisor } from './gateway-supervisor.ts';
import { clusterWorkerFactory } from './cluster-worker.ts';
import { ControlServer } from './control-server.ts';

// Secrets are supplied once via private stdin, never argv/environment/files baked into the image.
process.umask(0o077);
let supervisor: GatewaySupervisor | null = null, control: ControlServer | null = null, stopping = false;
async function stop(failed: boolean): Promise<void> {
  if (stopping) return; stopping = true;
  const timer = setTimeout(() => process.exit(1), 10000); timer.unref();
  try { await supervisor?.fence(failed ? 'unsafe-state' : 'operator-stop'); await control?.close(); }
  catch { failed = true; }
  if (failed) process.stderr.write('gateway-stopped\n');
  process.exit(failed ? 1 : 0);
}
process.on('SIGTERM', () => { void stop(false); });
process.on('SIGINT', () => { void stop(false); });
process.on('uncaughtException', () => { void stop(true); });
process.on('unhandledRejection', () => { void stop(true); });
try {
  if (process.platform !== 'linux' || Number(process.versions.node.split('.')[0]) !== 24 ||
    ['NODE_OPTIONS', 'DEBUG', 'NODE_V8_COVERAGE'].some(name => process.env[name]) || process.execArgv.length) throw Error();
  const input = await new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = []; let size = 0;
    const timer = setTimeout(() => reject(Error()), 5000);
    process.stdin.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > 131072) { process.stdin.destroy(); clearTimeout(timer); reject(Error()); return; }
      chunks.push(chunk);
    });
    process.stdin.once('error', () => { clearTimeout(timer); reject(Error()); });
    process.stdin.once('end', () => { clearTimeout(timer); resolve(Buffer.concat(chunks)); });
  });
  const config = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(input)) as Record<string, unknown>; input.fill(0);
  if (!config || Object.keys(config).sort().join(',') !== 'listen_host,redis,tls' || typeof config['listen_host'] !== 'string' ||
    !isIP(config['listen_host']) || ['0.0.0.0', '::'].includes(config['listen_host'])) throw Error();
  const redis = config['redis'] as Record<string, unknown>, tls = config['tls'] as { key: string; cert: string };
  if (!redis || Object.keys(redis).sort().join(',') !== 'password,username' || typeof redis['username'] !== 'string' ||
    !/^[a-zA-Z0-9_-]{1,64}$/.test(redis['username']) || typeof redis['password'] !== 'string' || redis['password'].length < 1 || redis['password'].length > 256 ||
    !tls || Object.keys(tls).sort().join(',') !== 'cert,key' || typeof tls.key !== 'string' || tls.key.length > 16384 || typeof tls.cert !== 'string' || tls.cert.length > 65536) throw Error();
  supervisor = new GatewaySupervisor(clusterWorkerFactory({ endpoint: { host: 'redis', port: 6379, username: redis['username'], password: redis['password'] },
    tls, listen_host: config['listen_host'], listen_port: 443 }));
  control = new ControlServer(supervisor); await control.listen();
} catch { await stop(true); }
