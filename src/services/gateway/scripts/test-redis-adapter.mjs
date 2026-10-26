import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
const root = fileURLToPath(new URL('../../../../', import.meta.url));
const redis = 'redis@sha256:efc27681bf81e6ed55cb581718b7818c6c04c39b1f9aa40854edd3ea2241b6ed';
const image = 'tokenforge-gateway:redis-adapter-tests';
function docker(args, inherit = false) {
  const result = spawnSync('docker', args, { cwd: root, encoding: 'utf8', shell: false,
    stdio: inherit ? 'inherit' : 'pipe', timeout: 180000, maxBuffer: 1024 * 1024 });
  if (result.error || result.status !== 0) throw Error('Redis adapter Docker check failed: ' + (result.stderr || result.error?.message || result.status));
  return result.stdout?.trim() ?? '';
}
docker(['build', '--target', 'redis-adapter-tests', '-f', 'src/services/gateway/Dockerfile', '-t', image, '.'], true);
let container = '';
try {
  container = docker(['run', '-d', '--rm', '--network', 'none', '--user', 'redis', '--read-only', '--tmpfs', '/data:rw,noexec,nosuid,size=8m',
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '384m', '--pids-limit', '64', '--log-driver', 'none',
    redis, 'redis-server', '--bind', '127.0.0.1', '--save', '', '--appendonly', 'no', '--maxmemory', '268435456',
    '--maxmemory-policy', 'noeviction', '--slowlog-log-slower-than', '-1', '--slowlog-max-len', '0', '--acllog-max-len', '0']);
  let ready = false;
  for (let attempt = 0; attempt < 20; attempt++) {
    try { ready = docker(['exec', container, 'redis-cli', 'PING']) === 'PONG'; } catch { /* isolated TEST startup only */ }
    if (ready) break;
    await delay(100);
  }
  if (!ready) throw Error('Isolated Redis did not become ready');
  docker(['run', '--rm', '--network', `container:${container}`, '--user', 'node', '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--memory', '256m', '--pids-limit', '64', image], true);
} finally { if (container) docker(['rm', '-f', container]); }
