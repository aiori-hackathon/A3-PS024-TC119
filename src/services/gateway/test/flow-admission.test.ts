import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { getEventListeners } from 'node:events';
import golden from '../../../contracts/fixtures/policy-golden.json' with { type: 'json' };
import { configurationDigest, makeManifest } from '../../../contracts/lib/index.ts';
import { WorkerLease, type LeaseRuntime } from '../src/worker-lease.ts';
import { FlowAdmission, type AdmissionResult, type FlowPermit } from '../src/flow-admission.ts';

const base = 10000000000n, ms = 1000000n;
const busy = { kind: 'rejected', reason: 'gateway-busy' };
const unavailable = { kind: 'rejected', reason: 'authorization-unavailable' };
function fixture(profile: 'B0' | 'B1' = 'B0') {
  const clock = { now: base };
  const timers: { callback: () => void; canceled: boolean; afterMs: number }[] = [];
  const runtime: LeaseRuntime = { nowNs: () => clock.now, schedule(afterMs, callback) {
    const timer = { callback, canceled: false, afterMs }; timers.push(timer); return () => { timer.canceled = true; };
  } };
  const m = makeManifest({ run_id: golden.manifest.run_id, run_start_ms: golden.manifest.run_start_ms,
    token_key_spki_b64url: golden.manifest.token_key_spki_b64url, snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40), gateway_profile: profile });
  const ids = { worker_incarnation: '1'.repeat(32), supervisor_incarnation: '2'.repeat(32) };
  const lease = WorkerLease.prepare(m, ids, () => {}, runtime);
  const queue = FlowAdmission.prepare(m, lease, runtime);
  function enable() {
    lease.markReady(); assert.equal(lease.enable({ version: 1, run_id: m.run_id, config_digest: configurationDigest(m), ...ids,
      sequence: 0, issued_at_ns: String(clock.now), expires_at_ns: String(clock.now + 3000n * ms) }), true);
  }
  return { m, lease, queue, clock, timers, runtime, enable };
}
function permit(result: AdmissionResult): FlowPermit {
  if (result.kind !== 'admitted') throw Error('Expected an active flow permit'); return result.permit;
}
const client = () => new AbortController();

test('profile limits reserve capacity before delivery and the FIFO queue is bounded at sixteen', async () => {
  for (const profile of ['B0', 'B1'] as const) {
    const f = fixture(profile); f.enable();
    const active = await Promise.all(Array.from({ length: profile === 'B0' ? 1 : 2 }, () => f.queue.acquire(client().signal)));
    assert.equal(f.queue.status.active, active.length);
    const waiting = Array.from({ length: 16 }, () => f.queue.acquire(client().signal));
    assert.equal(f.queue.status.queued, 16);
    assert.deepEqual(await f.queue.acquire(client().signal), busy);
    const drain = f.queue.close(); assert.deepEqual(await Promise.all(waiting), Array(16).fill(unavailable));
    active.forEach(r => permit(r).release()); await drain;
    assert.deepEqual(f.queue.status, { active: 0, queued: 0, closed: true }); f.lease.fence();
  }
});

test('FIFO promotion precedes new arrivals and double release never grants extra capacity', async () => {
  const f = fixture(); f.enable(); const a = permit(await f.queue.acquire(client().signal));
  const b = f.queue.acquire(client().signal), c = f.queue.acquire(client().signal);
  a.release(); a.release(); const d = f.queue.acquire(client().signal);
  const bp = permit(await b); assert.equal(f.queue.status.active, 1); assert.equal(f.queue.status.queued, 2);
  bp.release(); const cp = permit(await c); assert.equal(f.queue.status.queued, 1);
  cp.release(); const dp = permit(await d); dp.release(); await f.queue.close(); f.lease.fence();
});

test('already-disconnected and queued disconnected requests are removed with no promotion', async () => {
  const f = fixture(); f.enable(); const c = client(); c.abort();
  assert.deepEqual(await f.queue.acquire(c.signal), { kind: 'canceled' });
  const a = permit(await f.queue.acquire(client().signal)), queuedClient = client();
  const b = f.queue.acquire(queuedClient.signal); assert.equal(getEventListeners(queuedClient.signal, 'abort').length, 1);
  queuedClient.abort(); assert.deepEqual(await b, { kind: 'canceled' });
  assert.equal(f.queue.status.queued, 0); assert.equal(getEventListeners(queuedClient.signal, 'abort').length, 0);
  a.release(); assert.equal(f.queue.status.active, 0); await f.queue.close(); f.lease.fence();
});

test('active cancellation aborts work but holds its permit until actual cleanup releases it', async () => {
  const f = fixture(); f.enable(); const c = client(), a = permit(await f.queue.acquire(c.signal));
  const waiting = f.queue.acquire(client().signal); c.abort();
  assert.equal(a.signal.aborted, true); assert.equal(a.checkActive(), false);
  assert.deepEqual(f.queue.status, { active: 1, queued: 1, closed: false });
  a.release(); const b = permit(await waiting); assert.equal(b.checkActive(), true);
  b.release(); await f.queue.close(); f.lease.fence();
});

test('promotion checks the original 100ms boundary even before a delayed timeout callback', async () => {
  const f = fixture(); f.enable(); const a = permit(await f.queue.acquire(client().signal));
  const b = f.queue.acquire(client().signal); const timer = f.timers.at(-1)!;
  f.clock.now += 100n * ms; a.release();
  assert.deepEqual(await b, busy); assert.equal(f.queue.status.active, 0);
  timer.callback(); assert.equal(f.queue.status.active, 0);
  await f.queue.close(); f.lease.fence();
});

test('expired heads are removed, later eligible entries retain FIFO and fresh arrivals do not bypass them', async () => {
  const f = fixture(); f.enable(); const a = permit(await f.queue.acquire(client().signal));
  const expired = f.queue.acquire(client().signal); f.clock.now += 50n * ms;
  const eligible = f.queue.acquire(client().signal); f.clock.now += 50n * ms;
  const later = f.queue.acquire(client().signal); assert.deepEqual(await expired, busy);
  a.release(); const b = permit(await eligible); assert.equal(f.queue.status.queued, 1);
  b.release(); const c = permit(await later); c.release(); await f.queue.close(); f.lease.fence();
});

test('early queue timers preserve the deadline and canceled timers cannot cancel an active permit', async () => {
  const f = fixture(); f.enable(); const a = permit(await f.queue.acquire(client().signal));
  const waiting = f.queue.acquire(client().signal); const early = f.timers.at(-1)!;
  f.clock.now += 40n * ms; early.callback(); assert.equal(f.timers.at(-1)!.afterMs, 60);
  a.release(); const b = permit(await waiting); early.callback();
  assert.equal(b.checkActive(), true); assert.equal(b.signal.aborted, false);
  b.release(); await f.queue.close(); f.lease.fence();
});

test('lease expiry at promotion aborts active work and rejects the queue without releasing active capacity', async () => {
  const f = fixture(); f.enable(); const a = permit(await f.queue.acquire(client().signal));
  const b = f.queue.acquire(client().signal); f.clock.now += 3000n * ms;
  assert.equal(a.checkActive(), false); assert.deepEqual(await b, unavailable);
  assert.deepEqual(f.queue.status, { active: 1, queued: 0, closed: true });
  let drained = false; const closing = f.queue.close().then(() => { drained = true; });
  await Promise.resolve(); assert.equal(drained, false);
  a.release(); await closing; assert.equal(drained, true);
});

test('reentrant acquisition during closure sees terminal state and drain waits for every issued permit', async () => {
  const f = fixture('B1'); f.enable();
  const a = permit(await f.queue.acquire(client().signal)), b = permit(await f.queue.acquire(client().signal));
  const waiting = f.queue.acquire(client().signal); let reentrant: Promise<AdmissionResult> | undefined;
  a.signal.addEventListener('abort', () => { reentrant = f.queue.acquire(client().signal); a.release(); });
  const closing = f.queue.close(); assert.equal(f.queue.close(), closing);
  assert.deepEqual(await reentrant, unavailable); assert.deepEqual(await waiting, unavailable);
  assert.equal(f.queue.status.active, 1); b.release(); await closing; f.lease.fence();
});

test('client abort after promotion but before promise consumption produces an unusable held permit', async () => {
  const f = fixture(); f.enable(); const a = permit(await f.queue.acquire(client().signal)), c = client();
  const waiting = f.queue.acquire(c.signal); a.release(); c.abort();
  const b = permit(await waiting); assert.equal(b.checkActive(), false); assert.equal(b.signal.aborted, true);
  assert.equal(f.queue.status.active, 1); b.release(); await f.queue.close(); f.lease.fence();
});

test('admission clock and scheduler failures terminally close access without granting queued work', async () => {
  for (const mode of ['clock', 'schedule', 'cleanup']) {
    const f = fixture(); f.enable(); const a = permit(await f.queue.acquire(client().signal));
    if (mode === 'clock') f.clock.now = base - 1n;
    else if (mode === 'schedule') f.runtime.schedule = () => { throw Error('private timer detail'); };
    else f.runtime.schedule = () => () => { throw Error('private cancel detail'); };
    const waiting = f.queue.acquire(client().signal);
    if (mode === 'cleanup') a.release();
    assert.deepEqual(await waiting, unavailable); assert.equal(f.queue.status.closed, true);
    assert.equal(a.checkActive(), false); a.release(); await f.queue.close();
  }
});

test('configuration binding is immutable and prepared workers cannot admit requests', async () => {
  const f = fixture(); assert.deepEqual(await f.queue.acquire(client().signal), unavailable);
  const config = structuredClone(f.m), queue = FlowAdmission.prepare(config, f.lease, f.runtime);
  config.run_id = 'f'.repeat(32); f.enable(); const a = permit(await queue.acquire(client().signal));
  assert.equal(a.checkActive(), true); a.release(); await queue.close(); await f.queue.close(); f.lease.fence();
  assert.throws(() => FlowAdmission.prepare(config, f.lease), /admission-configuration-invalid/);
});

test('admission-clock regression faults the worker before reentrant cancellation handlers run', async () => {
  const f = fixture(); f.enable(); let queueNow = base;
  const queue = FlowAdmission.prepare(f.m, f.lease, { nowNs: () => queueNow, schedule: f.runtime.schedule });
  const a = permit(await queue.acquire(client().signal)); let activeDuringAbort: boolean | undefined;
  a.signal.addEventListener('abort', () => { activeDuringAbort = f.lease.checkActive(); });
  queueNow--;
  assert.deepEqual(await queue.acquire(client().signal), unavailable);
  assert.equal(activeDuringAbort, false); assert.equal(f.lease.status.fault, 'unsafe-state');
  assert.equal(queue.status.active, 1); a.release(); await queue.close(); await f.queue.close();
});

test('real queue timer rejects after the bounded wait without needing an active-flow release', async () => {
  const f = fixture(); f.enable(); const queue = FlowAdmission.prepare(f.m, f.lease);
  const a = permit(await queue.acquire(client().signal));
  const waiting = queue.acquire(client().signal);
  await delay(130); assert.deepEqual(await waiting, busy); assert.equal(queue.status.queued, 0);
  a.release(); await queue.close(); await f.queue.close(); f.lease.fence();
});
