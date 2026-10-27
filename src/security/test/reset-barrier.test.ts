import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate as turn } from 'node:timers/promises';
import golden from '../../contracts/fixtures/policy-golden.json' with { type: 'json' };
import { configurationDigest, validateManifest } from '../../contracts/lib/index.ts';
import { RESET_ROLES, ResetBarrier, type ResetAdapters, type ResetRuntime, type ResetTarget, type ResetReceipt } from '../reset-barrier.ts';

function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
function fixture() {
  const targets = RESET_ROLES.map((role, i) => ({ role, incarnation: (i + 1).toString(16).repeat(32), instance_id: (i + 1).toString(16).repeat(64) }));
  const generation = { manifest: structuredClone(golden.manifest), redis_instance_id: 'f'.repeat(64), participants: targets };
  let now = 1000000000n, discardCalls = 0;
  const timers = new Map<() => void, bigint>(), fenced: string[] = [], killed: string[] = [];
  const clock: ResetRuntime = { nowNs: () => now, schedule(ms, fn) { timers.set(fn, now + BigInt(ms) * 1000000n); return () => { timers.delete(fn); }; } };
  const ack = (target: ResetTarget, request: Readonly<Record<string, unknown>>, result = 'FENCED', data: unknown = {}) => ({
    version: 1, request_id: request['request_id'], ok: true, result, state: 'FENCED', run_id: golden.manifest.run_id,
    config_digest: configurationDigest(validateManifest(golden.manifest)), incarnation: target.incarnation, data });
  const exit = (target: ResetTarget) => ({ ...target, exited: true, descendants_exited: true });
  const adapters: ResetAdapters = {
    async fence(target, request) { fenced.push(target.role); return ack(target, request); },
    async terminate(target) { killed.push(target.role); return exit(target); },
    async reportOrigin(target, request) { return ack(target, request, 'REPORT', { counters: {
      protected_requests_received: 7, generation_mismatches: 2, resources_served: 5 }, measurements: [],
      same_source_observed: null, origin_counts_available: true, worker_verification_attempts: [] }); },
    async discardRedis(instance_id) { discardCalls++; return { instance_id, exited: true }; },
  };
  const make = () => ResetBarrier.prepare(generation, adapters, clock);
  return { generation, targets, adapters, clock, ack, exit, fenced, killed, make, calls: () => discardCalls,
    advance(ns: bigint, fire = true) { now += ns; if (fire) for (const [fn, at] of [...timers]) if (at <= now) { timers.delete(fn); fn(); } } };
}

test('complete distinct membership and immutable Redis/process identities are mandatory', () => {
  const f = fixture();
  for (const participants of [f.targets.slice(1), [...f.targets, f.targets[0]!], f.targets.map((t, i) => i ? t : f.targets[1]!),
    f.targets.map((t, i) => i ? t : { ...t, instance_id: 'container-name' }),
    f.targets.map((t, i) => i ? t : { ...t, instance_id: f.generation.redis_instance_id })]) {
    assert.throws(() => ResetBarrier.prepare({ ...f.generation, participants }, f.adapters), /reset-configuration-invalid/);
  }
});

test('all roles stop before an opaque receipt can discard the pinned old Redis once', async () => {
  const f = fixture(), barrier = f.make(), receipt = await barrier.fenceAll();
  assert.deepEqual(Object.keys(receipt), []); assert.ok(Object.isFrozen(receipt)); assert.equal(f.calls(), 0);
  assert.equal(barrier.status.participants_stopped, 8); assert.equal(barrier.status.origin_counts_available, true);
  assert.deepEqual(barrier.status.origin_counts, { protected_requests_received: 7, generation_mismatches: 2, resources_served: 5 });
  await barrier.discardOldRedis(receipt); assert.equal(f.calls(), 1); assert.equal(barrier.status.state, 'discarded');
  await assert.rejects(() => barrier.discardOldRedis(receipt), /reset-receipt-invalid/); assert.equal(f.calls(), 1);
});

test('pending participants block discard and reentrant fence calls return the cached promise', async () => {
  const f = fixture(), gate = deferred<unknown>();
  f.adapters.fence = async (target, request) => target.role === 'client-E' ? gate.promise : f.ack(target, request);
  const barrier = f.make(), waiting = barrier.fenceAll(); assert.equal(barrier.fenceAll(), waiting);
  await turn(); assert.equal(barrier.status.state, 'fencing'); assert.equal(f.calls(), 0);
  await assert.rejects(() => barrier.discardOldRedis({} as ResetReceipt), /reset-receipt-invalid/);
  gate.resolve({}); await waiting; assert.ok(f.killed.includes('client-E')); assert.equal(f.calls(), 0);
});

test('wrong request/run/config/incarnation/state FENCE evidence takes identity-bound termination fallback', async () => {
  for (const change of [{ request_id: 'f'.repeat(32) }, { run_id: 'f'.repeat(32) }, { config_digest: 'f'.repeat(64) },
    { incarnation: 'f'.repeat(32) }, { state: 'ENABLED' }, { ok: false, result: 'FAULTED' }]) {
    const f = fixture(); f.adapters.fence = async (target, request) => target.role === 'gateway' ? { ...f.ack(target, request), ...change } : f.ack(target, request);
    const barrier = f.make(); await barrier.fenceAll(); assert.deepEqual(f.killed, ['gateway']);
    assert.equal(barrier.status.roles.find(r => r.role === 'gateway')!.method, 'terminated');
  }
});

test('one unconfirmed descendant exit blocks the whole barrier and exposes no discard receipt', async () => {
  const f = fixture(); f.adapters.fence = async (target, request) => target.role === 'gateway' ? {} : f.ack(target, request);
  f.adapters.terminate = async target => ({ ...f.exit(target), descendants_exited: false });
  const barrier = f.make(), attempt = barrier.fenceAll(); await assert.rejects(attempt, /reset-barrier-unconfirmed/);
  assert.equal(barrier.fenceAll(), attempt); assert.equal(barrier.status.state, 'blocked'); assert.equal(f.calls(), 0);
});

test('synchronous adapter exceptions do not skip stopping other participants', async () => {
  const f = fixture(); f.adapters.fence = (target, request) => {
    f.fenced.push(target.role); if (target.role === 'issuer') throw Error('private exception'); return Promise.resolve(f.ack(target, request));
  };
  f.adapters.terminate = () => { throw Error('private kill failure'); };
  const barrier = f.make(); await assert.rejects(barrier.fenceAll(), /reset-barrier-unconfirmed/);
  assert.equal(f.fenced.length, 8); assert.equal(f.calls(), 0);
});

test('a timed-out FENCE cannot replace the selected kill path with a late success', async () => {
  const f = fixture(), fence = deferred<unknown>(), killed = deferred<unknown>(); let request: Readonly<Record<string, unknown>>;
  f.adapters.fence = async (target, r) => { if (target.role === 'gateway') { request = r; return fence.promise; } return f.ack(target, r); };
  f.adapters.terminate = async () => killed.promise;
  const barrier = f.make(), pending = barrier.fenceAll(); await turn(); f.advance(10000000000n); await turn();
  fence.resolve(f.ack(f.targets[0]!, request!)); await turn(); assert.equal(barrier.status.state, 'fencing'); assert.equal(f.calls(), 0);
  killed.resolve(f.exit(f.targets[0]!)); await pending; assert.equal(barrier.status.roles[0]!.method, 'terminated');
});

test('post-deadline termination success is rejected even before a delayed timer executes', async () => {
  const f = fixture(); f.adapters.fence = async () => ({});
  f.adapters.terminate = async target => { if (target.role === 'client-E') f.advance(10000000000n, false); return f.exit(target); };
  const barrier = f.make(); await assert.rejects(barrier.fenceAll(), /reset-barrier-unconfirmed/); assert.equal(f.calls(), 0);
});

test('termination evidence must identify the original process, not a replacement or reusable PID', async () => {
  for (const change of [{ instance_id: 'e'.repeat(64) }, { incarnation: 'e'.repeat(32) }, { role: 'origin' }, { exited: false }]) {
    const f = fixture(); f.adapters.fence = async (target, request) => target.role === 'gateway' ? {} : f.ack(target, request);
    f.adapters.terminate = async target => ({ ...f.exit(target), ...change });
    await assert.rejects(f.make().fenceAll(), /reset-barrier-unconfirmed/); assert.equal(f.calls(), 0);
  }
});

test('killed origin evidence is unavailable rather than zero; safe teardown can still proceed', async () => {
  const f = fixture(); f.adapters.fence = async (target, request) => target.role === 'origin' ? {} : f.ack(target, request);
  f.adapters.reportOrigin = () => { throw Error('must not read killed origin'); };
  const barrier = f.make(), receipt = await barrier.fenceAll();
  assert.equal(barrier.status.origin_counts_available, false); assert.equal(barrier.status.origin_counts, null);
  await barrier.discardOldRedis(receipt); assert.equal(f.calls(), 1);
});

test('missing, inconsistent or nonsettled origin reports never invent final counters', async () => {
  for (const report of ['throw', 'not-fenced', 'missing', 'inconsistent']) {
    const f = fixture(); f.adapters.reportOrigin = async (target, request) => {
      if (report === 'throw') throw Error('report lost');
      return { ...f.ack(target, request, 'REPORT', { counters: report === 'missing' ? {} : {
        protected_requests_received: 1, generation_mismatches: 1, resources_served: 1 }, measurements: [],
        same_source_observed: null, origin_counts_available: true, worker_verification_attempts: [] }), ...(report === 'not-fenced' ? { state: 'ENABLED' } : {}) };
    };
    const barrier = f.make(), receipt = await barrier.fenceAll(); assert.equal(barrier.status.origin_counts, null); await barrier.discardOldRedis(receipt);
  }
});

test('forged, cloned and other-barrier receipts cannot trigger Redis discard', async () => {
  const f = fixture(), g = fixture(), first = f.make(), second = g.make();
  const receipt = await first.fenceAll(); await second.fenceAll();
  await assert.rejects(() => first.discardOldRedis(structuredClone(receipt)), /reset-receipt-invalid/);
  await assert.rejects(() => second.discardOldRedis(receipt), /reset-receipt-invalid/);
  assert.equal(f.calls(), 0); assert.equal(g.calls(), 0);
});

test('concurrent and reentrant consumption invokes the discard adapter at most once', async () => {
  const f = fixture(), gate = deferred<unknown>(); let calls = 0, receipt: ResetReceipt, nested: Promise<void>;
  let barrier: ResetBarrier;
  f.adapters.discardRedis = async () => { calls++; nested = barrier.discardOldRedis(receipt); nested.catch(() => {}); return gate.promise; };
  barrier = f.make(); receipt = await barrier.fenceAll(); const first = barrier.discardOldRedis(receipt);
  await assert.rejects(() => barrier.discardOldRedis(receipt), /reset-receipt-invalid/); await assert.rejects(nested!, /reset-receipt-invalid/);
  gate.resolve({ instance_id: f.generation.redis_instance_id, exited: true }); await first; assert.equal(calls, 1);
});

test('discard failure or mismatched exit confirmation is terminal and never retried', async () => {
  for (const outcome of ['throw', 'wrong-instance', 'not-exited']) {
    const f = fixture(); let calls = 0;
    f.adapters.discardRedis = async instance_id => { calls++; if (outcome === 'throw') throw Error('commit response lost');
      return { instance_id: outcome === 'wrong-instance' ? 'e'.repeat(64) : instance_id, exited: outcome !== 'not-exited' }; };
    const barrier = f.make(), receipt = await barrier.fenceAll();
    await assert.rejects(() => barrier.discardOldRedis(receipt), /reset-discard-unconfirmed/);
    await assert.rejects(() => barrier.discardOldRedis(receipt), /reset-receipt-invalid/);
    assert.equal(barrier.status.state, 'uncertain'); assert.equal(calls, 1);
  }
});

test('manifest/target/adapter-table mutation cannot retarget the captured old Redis or roles', async () => {
  const f = fixture(), barrier = f.make();
  f.generation.redis_instance_id = 'e'.repeat(64); f.generation.participants[0]!.instance_id = 'e'.repeat(64);
  f.adapters.discardRedis = () => { throw Error('replaced callback'); };
  const receipt = await barrier.fenceAll(); await barrier.discardOldRedis(receipt); assert.equal(f.calls(), 1);
});

test('monotonic clock failure blocks reset while still requesting emergency role termination', async () => {
  const f = fixture(); let clock = 100n;
  const barrier = ResetBarrier.prepare(f.generation, f.adapters, { nowNs: () => clock--, schedule: () => () => {} });
  await assert.rejects(barrier.fenceAll(), /reset-barrier-unconfirmed/); assert.equal(f.calls(), 0); assert.ok(f.killed.length > 0);
});
