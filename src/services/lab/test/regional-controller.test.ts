import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DockerAdapters, DockerProject, SERVICE_FOR_ROLE, type DockerCli, type RunResult } from '../src/controller/docker.ts';
import { RegionalLab, regionalEvidenceState } from '../src/controller/regional-runtime.ts';
import type { RoleLink } from '../src/controller/ports.ts';

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
const tick = () => new Promise<void>(resolve => setImmediate(resolve));

/** Only container identity/state is modelled. No application traffic is simulated. */
class DelayedDocker implements DockerCli {
  entered = deferred<void>();
  release = deferred<void>();
  containers = new Map<string, { id: string; running: boolean }>();
  removedRedis = 0;
  spawned = 0;
  upCalls = 0;
  async run(args: string[]): Promise<RunResult> {
    const reply = (stdout = '', status = 0, stderr = '') => ({ stdout, status, stderr, timedOut: false, failed: false });
    if (args[0] === 'compose') {
      if (args[3] === 'up') {
        this.upCalls++;
        this.entered.resolve();
        await this.release.promise;
        for (const [index, service] of [...Object.values(SERVICE_FOR_ROLE), 'redis'].entries()) {
          this.containers.set(service, { id: (this.upCalls * 16 + index + 1).toString(16).padStart(64, '0'), running: true });
        }
      } else if (args[3] === 'ps') {
        return reply(this.containers.get(args.at(-1)!)?.id ?? '');
      } else throw Error('unexpected-compose-command');
      return reply();
    }
    const id = args.at(-1)!;
    const container = [...this.containers.values()].find(value => value.id === id);
    if (args[0] === 'inspect') {
      if (!container) return reply('', 1, `error: no such object: ${id}`);
      return reply(args[2] === '{{.Id}}' ? id : `${id} ${container.running} ${container.running ? 'running' : 'exited'}`);
    }
    if (args[0] === 'kill' && container) { container.running = false; return reply(); }
    if (args[0] === 'rm') {
      assert.ok([...this.containers.entries()].every(([service, value]) => service === 'redis' || !value.running));
      this.containers.delete('redis');
      this.removedRedis++;
      return reply();
    }
    throw Error('unexpected-docker-command');
  }
  spawn(): never { this.spawned++; throw Error('unexpected-process-launch'); }
}

function fixture(t: { after: (cleanup: () => void) => void }) {
  const root = mkdtempSync(join(tmpdir(), 'regional-close-'));
  mkdirSync(join(root, '.runtime'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const docker = new DelayedDocker();
  const lab = new RegionalLab(root, { docker, prepareImages: async () => {} });
  return { root, docker, lab, lock: join(root, '.runtime', 'project.lock') };
}

test('close drains delayed Compose and late resources before releasing ownership, then allows a fresh experiment', async t => {
  const { docker, lab, lock } = fixture(t);
  for (let experiment = 0; experiment < 2; experiment++) {
    const starting = lab.execute({ action: 'start_run', profile: 'ip' });
    await docker.entered.promise;
    assert.ok(existsSync(lock));
    const closing = lab.close();
    assert.equal(lab.close(), closing);
    let closed = false;
    void closing.then(() => { closed = true; });
    await tick();
    assert.equal(closed, false);
    assert.ok(existsSync(lock));
    await assert.rejects(lab.execute({ action: 'start_run', profile: 'ip' }));
    docker.release.resolve();
    const [result] = await Promise.all([starting, closing]);
    assert.equal(result.outcome, 'uncertain');
    assert.equal(lab.status().state, 'idle');
    assert.equal(existsSync(lock), false);
    assert.ok([...docker.containers.values()].every(value => !value.running));
    assert.equal(docker.spawned, 0);
    docker.entered = deferred<void>();
    docker.release = deferred<void>();
  }
  assert.equal(docker.upCalls, 2);
  assert.equal(docker.removedRedis, 2);
});

test('a readiness link arriving after cancellation is disposed before close completes', async t => {
  const { docker, lab, lock } = fixture(t);
  const entered = deferred<void>();
  const readiness = deferred<Record<string, unknown>>();
  let linkClosed = false;
  const link: RoleLink = {
    role: 'issuer', send: () => { entered.resolve(); return readiness.promise; },
    close: () => { linkClosed = true; },
  };
  t.mock.method(DockerProject.prototype, 'openLink', () => link);
  docker.release.resolve();
  const starting = lab.execute({ action: 'start_run', profile: 'ip' });
  await entered.promise;
  const closing = lab.close();
  await tick();
  assert.ok(existsSync(lock));
  readiness.resolve({ ok: true });
  await Promise.all([starting, closing]);
  assert.equal(linkClosed, true);
  assert.equal(existsSync(lock), false);
  assert.equal(docker.removedRedis, 1);
});

test('unconfirmed late-resource cleanup retains the project lock and Redis', async t => {
  const { docker, lab, lock } = fixture(t);
  t.mock.method(DockerAdapters.prototype, 'terminate', async () => { throw Error('exit-unconfirmed'); });
  const starting = lab.execute({ action: 'start_run', profile: 'ip' }).catch(error => error);
  await docker.entered.promise;
  const closing = lab.close();
  const failedClose = assert.rejects(closing, /shutdown-unconfirmed/);
  docker.release.resolve();
  await starting;
  await failedClose;
  assert.ok(existsSync(lock));
  assert.equal(lab.status().state, 'error');
  assert.equal(docker.removedRedis, 0);
});

test('verified delivery requires matching independently received and served deltas', () => {
  const before = { protected_requests_received: 3, resources_served: 3, generation_mismatches: 0 };
  assert.equal(regionalEvidenceState(before, { ...before, protected_requests_received: 4, resources_served: 4 }, 1), 'verified');
  assert.equal(regionalEvidenceState(before, { ...before, protected_requests_received: 4 }, 1), 'mismatch');
  assert.equal(regionalEvidenceState(before, { ...before, resources_served: 4 }, 1), 'mismatch');
  assert.equal(regionalEvidenceState(before, { ...before, generation_mismatches: 1 }, 0), 'mismatch');
  assert.equal(regionalEvidenceState(before, null, 1), 'incomplete');
});
