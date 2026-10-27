import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate as turn } from 'node:timers/promises';
import golden from '../../../contracts/fixtures/policy-golden.json' with { type: 'json' };
import { configurationDigest, validateManifest } from '../../../contracts/lib/index.ts';
import { WorkerLease } from '../src/worker-lease.ts';
import { RequestCoordinator, type RequestView, type CoordinatorResponse } from '../src/request-coordinator.ts';
import type { ReplaySnapshot } from '../src/replay-store.ts';

async function fixture(onClose?: () => void) {
  const m = validateManifest(structuredClone(golden.manifest)), digest = configurationDigest(m), abort = new AbortController();
  const ids = { worker_incarnation: '1'.repeat(32), supervisor_incarnation: '2'.repeat(32) };
  const lease = WorkerLease.prepare(m, ids, () => onClose?.());
  let snapshots = 0, forwards = 0, closed = false, replayCloses = 0, originCloses = 0;
  const replay = {
    binding: { run_id: m.run_id, config_digest: digest }, signal: abort.signal,
    get status() { return { state: closed ? 'closed' as const : 'ready' as const, fault: null }; },
    async snapshot(): Promise<ReplaySnapshot> {
      snapshots++;
      return { kind: 'snapshot', now_ms: m.run_start_ms + 1, epoch: 0, start_ms: m.run_start_ms, end_ms: m.run_start_ms + m.epoch_ms,
        reply: ['SNAPSHOT', m.run_id, m.token_key_id, digest, m.run_start_ms + 1, 0, m.run_start_ms, m.run_start_ms + m.epoch_ms] };
    },
    async claim(): Promise<never> { throw Error('No test request should claim'); },
    close() { replayCloses++; closed = true; abort.abort(); },
  };
  const origin = { binding: { run_id: m.run_id, config_digest: digest }, status: { closed: false, active: 0, sockets: 0, idle: 0, queued: 0 },
    async forwardAfterClaim(): Promise<never> { forwards++; throw Error('No test request should forward'); }, async close() { originCloses++; } };
  const coordinator = await RequestCoordinator.prepare(m, lease, replay, origin);
  const issued = process.hrtime.bigint();
  lease.enable({ version: 1, run_id: m.run_id, config_digest: digest, ...ids, sequence: 0,
    issued_at_ns: String(issued), expires_at_ns: String(issued + 3000000000n) });
  const view = (): RequestView => ({ method: 'GET', target: '/resource', rawHeaders: ['Host', m.origin_name], hasBody: false, signal: new AbortController().signal });
  const response = async (v = view()) => { const out: CoordinatorResponse[] = []; await coordinator.handle(v, async r => { out.push(r); }); return out[0]!; };
  return { m, ids, lease, replay, origin, coordinator, view, response, counts: () => ({ snapshots, forwards }),
    cleanupCounts: () => ({ replay: replayCloses, origin: originCloses }) };
}

test('preflight ordering and framing reject before any replay or origin work', async () => {
  const f = await fixture();
  const cases: [Partial<RequestView>, number][] = [
    [{ rawHeaders: ['Host', 'other.test'], target: '/bad', method: 'POST', hasBody: true }, 421],
    [{ target: '/resource?token=forbidden', method: 'POST', hasBody: true }, 404],
    [{ method: 'POST', hasBody: true }, 405], [{ hasBody: true }, 400],
    [{ rawHeaders: ['Host', f.m.origin_name, 'Content-Length', '00'] }, 400],
    [{ rawHeaders: ['Host', f.m.origin_name, 'Content-Length', '0', 'content-length', '0'] }, 400],
    [{ rawHeaders: ['Host', f.m.origin_name, 'Transfer-Encoding', 'chunked'] }, 400],
    [{ rawHeaders: ['Host', f.m.origin_name, 'Expect', '100-continue'] }, 400],
    [{ rawHeaders: ['Host', f.m.origin_name, 'Host', f.m.origin_name] }, 400],
    [{ rawHeaders: ['Host', f.m.origin_name, 'X-Test', 'x'.repeat(8192)] }, 400],
  ];
  for (const [change, status] of cases) assert.equal((await f.response({ ...f.view(), ...change })).status, status);
  assert.deepEqual(f.counts(), { snapshots: 0, forwards: 0 }); await f.coordinator.close();
});

test('missing credentials obtain a valid current challenge; malformed credentials do not spend', async () => {
  const f = await fixture(); const missing = await f.response();
  assert.equal(missing.status, 401); assert.ok('headers' in missing && missing.headers['www-authenticate']);
  const bad = await f.response({ ...f.view(), rawHeaders: ['Host', f.m.origin_name, 'Authorization', 'PrivateToken token=bad'] });
  assert.equal(bad.status, 400); assert.deepEqual(f.counts(), { snapshots: 1, forwards: 0 }); await f.coordinator.close();
});

test('response sink settlement retains permits, and queued metadata is owned before the first await', async () => {
  const f = await fixture(); const releases: (() => void)[] = [];
  const hold = async () => new Promise<void>(resolve => releases.push(resolve));
  const first = f.coordinator.handle(f.view(), hold), second = f.coordinator.handle(f.view(), hold);
  await turn(); assert.equal(releases.length, 2); assert.equal(f.coordinator.status.active, 2);
  const v = f.view(); const pending = f.response(v);
  (v.rawHeaders as string[])[1] = 'other.test'; v.method = 'POST'; v.target = '/bad'; v.hasBody = true;
  releases[0]!(); assert.equal((await pending).status, 401);
  releases[1]!(); await Promise.all([first, second]); assert.equal(f.coordinator.status.active, 0); await f.coordinator.close();
});

test('sink failure is not followed by a replacement response and does not fault a healthy worker', async () => {
  const f = await fixture(); let writes = 0;
  await f.coordinator.handle(f.view(), async () => { writes++; throw Error('private downstream detail'); });
  assert.equal(writes, 1); assert.equal(f.coordinator.status.active, 0); assert.equal(f.lease.status.state, 'ENABLED');
  await f.coordinator.close();
});

test('idle replay closure immediately faults the worker and dependency bindings must match', async () => {
  const f = await fixture(); f.replay.close();
  assert.equal(f.lease.status.run_closed, true); assert.equal(f.lease.status.fault, 'dependency-lost');
  assert.equal((await f.response()).status, 503); assert.equal(f.counts().forwards, 0); await f.coordinator.close();
  const lease = WorkerLease.prepare(f.m, f.ids, () => {});
  await assert.rejects(() => RequestCoordinator.prepare(f.m, lease, { ...f.replay,
    binding: { run_id: 'f'.repeat(32), config_digest: configurationDigest(f.m) } }, f.origin), /coordinator-configuration-invalid/);
});

test('reentrant shutdown returns one published promise and invokes each dependency cleanup once', async () => {
  let ref: RequestCoordinator | undefined, nested: Promise<void> | undefined;
  const f = await fixture(() => { nested = ref!.close(); }); ref = f.coordinator;
  const closing = f.coordinator.close(); assert.equal(nested, closing); await closing;
  assert.deepEqual(f.cleanupCounts(), { replay: 1, origin: 1 });
});

test('shutdown cancels a stalled response sink but waits for its actual cleanup and permit release', async () => {
  const f = await fixture(); let finish!: () => void, aborted = false;
  const request = f.coordinator.handle(f.view(), async (_response, signal) => {
    signal.addEventListener('abort', () => { aborted = true; }, { once: true });
    await new Promise<void>(resolve => { finish = resolve; });
  });
  await turn(); let drained = false;
  const closing = f.coordinator.close().then(() => { drained = true; });
  try {
    await turn(); assert.equal(aborted, true); assert.equal(drained, false); assert.equal(f.coordinator.status.active, 1);
  } finally { finish(); await request; await closing; }
  assert.equal(f.coordinator.status.active, 0);
});

test('a failed final challenge snapshot becomes503 without a challenge or forwarding', async () => {
  const f = await fixture(); f.replay.snapshot = async () => ({ kind: 'unavailable' });
  const response = await f.response();
  assert.equal(response.status, 503); assert.ok('headers' in response && !response.headers['www-authenticate']);
  assert.equal(f.lease.status.run_closed, true); assert.equal(f.counts().forwards, 0); await f.coordinator.close();
});
