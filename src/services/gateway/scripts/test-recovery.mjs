import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createTestTls } from './create-test-tls.ts';
import { validateManifest } from '../../../contracts/lib/index.ts';

const root = fileURLToPath(new URL('../../../../', import.meta.url));
const redisImage = 'redis@sha256:efc27681bf81e6ed55cb581718b7818c6c04c39b1f9aa40854edd3ea2241b6ed';
const phaseImage = 'tokenforge-gateway:recovery-tests';
// ALL Docker stdout/stderr stays captured. A phase's private stdout contains quarantined old credentials.
function docker(args, input, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const child = execFile('docker', args, { cwd: root, encoding: 'utf8', windowsHide: true, timeout, maxBuffer: 1024 * 1024 },
      (error, stdout) => error ? reject(Error('recovery-docker-operation-failed')) : resolve(stdout.trim()));
    child.stdin.end(input);
  });
}
async function inspect(id) {
  const value = JSON.parse(await docker(['inspect', id]));
  if (value.length !== 1 || value[0].Id !== id) throw Error('recovery-instance-mismatch');
  return value[0];
}
test('fresh Redis/key/run rejects spent AND unused old credentials; fresh token reaches new origin once', { timeout: 180000 }, async () => {
  await docker(['build', '--target', 'recovery-tests', '-f', 'src/services/gateway/Dockerfile', '-t', phaseImage, '.'], undefined, 120000);
  const tls = await createTestTls(), containers = new Set();
  const label = 'tokenforge.test.recovery=' + randomBytes(16).toString('hex');
  const register = id => { if (!/^[0-9a-f]{64}$/.test(id)) throw Error('recovery-instance-invalid'); containers.add(id); return id; };
  let previous = null;
  async function startRedis() {
    const id = register(await docker(['run', '-d', '--label', label, '--network', 'none', '--user', 'redis', '--read-only',
      '--add-host', 'redis:127.0.0.1', '--add-host', 'protected-origin:127.0.0.1',
      '--tmpfs', '/data:rw,noexec,nosuid,size=8m', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
      '--memory', '384m', '--pids-limit', '64', '--log-driver', 'none', redisImage, 'redis-server',
      '--bind', '127.0.0.1', '--save', '', '--appendonly', 'no', '--maxmemory', '268435456', '--maxmemory-policy', 'noeviction',
      '--slowlog-log-slower-than', '-1', '--slowlog-max-len', '0', '--acllog-max-len', '0']));
    for (let i = 0; i < 30; i++) { try { if (await docker(['exec', id, 'redis-cli', 'PING']) === 'PONG') return id; } catch { /* TEST startup only */ } }
    throw Error('recovery-redis-not-ready');
  }
  async function phase(redis, kind, old) {
    const id = register(await docker(['create', '-i', '--label', label, '--network', `container:${redis}`, '--user', 'node', '--read-only',
      '--tmpfs', '/run/ps024:rw,noexec,nosuid,mode=0700,uid=1000,gid=1000,size=1m', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
      '--memory', '256m', '--pids-limit', '64', '--log-driver', 'none', phaseImage]));
    const config = { phase: kind, tls, password: randomBytes(32).toString('hex'), ...(old ? { previous: old } : {}) };
    const captured = await docker(['start', '-a', '-i', id], JSON.stringify(config), 45000);
    const state = (await inspect(id)).State;
    if (state.Running || state.Pid !== 0 || state.ExitCode !== 0 || state.OOMKilled) throw Error('recovery-phase-exit-unconfirmed');
    let result;
    try { result = JSON.parse(captured); } catch { throw Error('recovery-private-result-invalid'); }
    validateManifest(result.manifest);
    if (result.phase !== kind || result.received !== 1 || result.served !== 1 || result.mismatches !== 0 ||
      typeof result.gateway_incarnation !== 'string' || !/^[0-9a-f]{32}$/.test(result.gateway_incarnation)) throw Error('recovery-evidence-invalid');
    // A confirmed stopped phase container proves its actual gateway/fixture processes exited.
    // It does NOT fabricate exit proofs for eight deployed issuer/client/origin role instances.
    await docker(['rm', id]); containers.delete(id); return result;
  }
  try {
    const oldRedis = await startRedis(), old = await phase(oldRedis, 'old');
    const quarantine = old.quarantine;
    if (!quarantine || !['spent', 'unused'].every(name => typeof quarantine[name] === 'string' && /^[A-Za-z0-9_-]{472}$/.test(quarantine[name]))) throw Error('recovery-private-fixture-invalid');
    previous = { run_id: old.manifest.run_id, token_key_id: old.manifest.token_key_id, ...quarantine };
    // No old-state mutation before the entire actual old phase has exited, including all workers.
    await docker(['stop', '--time', '1', oldRedis]);
    const stopped = (await inspect(oldRedis)).State;
    if (stopped.Running || stopped.Pid !== 0) throw Error('recovery-old-redis-exit-unconfirmed');
    await docker(['rm', oldRedis]); containers.delete(oldRedis);
    const newRedis = await startRedis(); assert.notEqual(newRedis, oldRedis);
    const fresh = await phase(newRedis, 'fresh', previous);
    assert.notEqual(fresh.manifest.run_id, old.manifest.run_id); assert.notEqual(fresh.manifest.token_key_id, old.manifest.token_key_id);
    assert.notEqual(fresh.gateway_incarnation, old.gateway_incarnation);
  } finally {
    if (previous) { previous.spent = ''; previous.unused = ''; }
    let cleanupFailed = false;
    // Include an uncertain create whose CLI reply may have been lost. Only this unique test label is eligible.
    try { for (const id of (await docker(['ps', '-aq', '--no-trunc', '--filter', `label=${label}`])).split(/\s+/).filter(Boolean)) register(id); }
    catch { cleanupFailed = true; }
    for (const id of containers) { try { await docker(['rm', '-f', id]); } catch { cleanupFailed = true; } }
    try { if (await docker(['ps', '-aq', '--filter', `label=${label}`])) cleanupFailed = true; } catch { cleanupFailed = true; }
    if (cleanupFailed) throw Error('recovery-cleanup-unconfirmed');
  }
});
