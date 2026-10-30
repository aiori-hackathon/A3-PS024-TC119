import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate as turn } from 'node:timers/promises';
import { randomBytes } from 'node:crypto';
import golden from '../../../contracts/fixtures/policy-golden.json' with { type: 'json' };
import { configurationDigest, makeManifest, validateManifest } from '../../../contracts/lib/index.ts';
import { GatewaySupervisor, type SupervisorWorker } from '../src/gateway-supervisor.ts';
import type { LeaseRuntime, WorkerCloseReason, WorkerLeaseGrant } from '../src/worker-lease.ts';

function deferred() { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; }
function fixture(profile: 'B0' | 'B1' = 'B1') {
  const m = makeManifest({ ...validateManifest(golden.manifest), gateway_profile: profile });
  let now = 1000000000n;
  const runtime: LeaseRuntime = { nowNs: () => now, schedule: () => () => {} };
  const workers: (SupervisorWorker & { enables: WorkerLeaseGrant[]; beats: WorkerLeaseGrant[]; listens: number; closes: number })[] = [];
  const faults: ((reason: WorkerCloseReason) => void)[] = [];
  const supervisor = new GatewaySupervisor(async (index, fault) => {
    faults[index] = fault;
    const worker = { incarnation: String(index + 1).repeat(32), enables: [] as WorkerLeaseGrant[], beats: [] as WorkerLeaseGrant[], listens: 0, closes: 0,
      async prepare() {}, async enable(grant: WorkerLeaseGrant) { this.enables.push(grant); }, async listen() { this.listens++; },
      async heartbeat(grant: WorkerLeaseGrant) { this.beats.push(grant); }, async attempts() { return index + 1; }, async close() { this.closes++; } };
    workers[index] = worker; return worker;
  }, runtime);
  const message = (command: string, payload: unknown = {}, extra: Record<string, unknown> = {}) => ({ version: 1,
    request_id: randomBytes(16).toString('hex'), command, run_id: m.run_id,
    config_digest: supervisor.status.config_digest, target_incarnation: supervisor.incarnation, payload, ...extra });
  const prepare = () => supervisor.handle(message('PREPARE_RUN', { manifest: m, proposed_config_digest: configurationDigest(m), role: 'gateway', role_config: {} }, { config_digest: null }));
  const ready = async () => { assert.equal((await prepare())['ok'], true); assert.equal((await supervisor.handle(message('CHECK_READY')))['ok'], true); };
  return { m, supervisor, workers, faults, message, prepare, ready, advance(ns: bigint) { now += ns; } };
}

test('both profiles require all configured workers and install every lease before listening', async () => {
  for (const profile of ['B0', 'B1'] as const) {
    const f = fixture(profile); await f.ready();
    const gate = deferred(), last = f.workers.at(-1)!;
    last.enable = async grant => { last.enables.push(grant); await gate.promise; };
    const enabling = f.supervisor.handle(f.message('ENABLE')); await turn();
    assert.equal(f.workers.reduce((n, w) => n + w.listens, 0), 0);
    gate.resolve(); const response = await enabling;
    assert.equal(response['ok'], true); assert.equal(f.workers.length, profile === 'B0' ? 1 : 2);
    assert.ok(f.workers.every(w => w.listens === 1));
    assert.ok(f.workers.every(w => w.enables[0]!.expires_at_ns === '4000000000'));
    await f.supervisor.fence();
  }
});

test('repeat ENABLE never renews a lease and a late heartbeat cannot revive an expired run', async () => {
  const f = fixture(); await f.ready(); await f.supervisor.handle(f.message('ENABLE'));
  f.advance(2999000000n); assert.equal((await f.supervisor.handle(f.message('ENABLE')))['ok'], true);
  assert.ok(f.workers.every(w => w.enables.length === 1));
  f.advance(1000000n); assert.equal((await f.supervisor.handle(f.message('HEARTBEAT', { seq: 1 })))['ok'], false);
  assert.equal(f.supervisor.status.run_closed, true); assert.equal(f.supervisor.status.fault, 'lease-expired');
  await f.supervisor.fence();
});

test('one heartbeat is outstanding, all grants preserve its original stamp and duplicate seq does not renew', async () => {
  const f = fixture(); await f.ready(); await f.supervisor.handle(f.message('ENABLE')); f.advance(1000000000n);
  const gate = deferred(), last = f.workers[1]!;
  last.heartbeat = async grant => { last.beats.push(grant); await gate.promise; };
  const heartbeat = f.supervisor.handle(f.message('HEARTBEAT', { seq: 3 })); await turn();
  assert.equal((await f.supervisor.handle(f.message('HEARTBEAT', { seq: 4 })))['ok'], false);
  assert.ok(f.workers.every(w => w.beats[0]!.expires_at_ns === '5000000000'));
  gate.resolve(); assert.equal((await heartbeat)['ok'], true);
  assert.equal((await f.supervisor.handle(f.message('HEARTBEAT', { seq: 3 })))['ok'], false); await f.supervisor.fence();
});

test('FENCE interrupts pending ENABLE, remains responsive, and cannot produce a late listener', async () => {
  const f = fixture(); await f.ready(); const gate = deferred(); f.workers[1]!.enable = () => gate.promise;
  const enabling = f.supervisor.handle(f.message('ENABLE')); await turn();
  assert.equal((await f.supervisor.handle(f.message('STATUS')))['ok'], true);
  const fenced = await f.supervisor.handle(f.message('FENCE', { reason: 'operator-stop' }, { target_incarnation: null, run_id: null, config_digest: null }));
  assert.equal(fenced['result'], 'FENCED'); gate.resolve(); assert.equal((await enabling)['ok'], false);
  assert.ok(f.workers.every(w => w.listens === 0)); assert.equal((await f.prepare())['ok'], false);
});

test('FENCE waits for confirmed worker exit; reentrant closure shares a promise', async () => {
  const f = fixture(), exitGate = deferred();
  const preparing = f.prepare(); await turn();
  await preparing;
  f.workers[0]!.close = () => exitGate.promise;
  const closing = f.supervisor.fence(), again = f.supervisor.fence(); assert.equal(closing, again);
  let settled = false; closing.then(() => { settled = true; }); await turn(); assert.equal(settled, false);
  exitGate.resolve(); await closing; assert.equal(f.supervisor.status.run_closed, true);
});

test('a LISTEN failure or worker fault closes every sibling and preserves the terminal run', async () => {
  const f = fixture(); await f.ready(); f.workers[1]!.listen = async () => { throw Error('private native detail'); };
  const reply = await f.supervisor.handle(f.message('ENABLE')); assert.equal(reply['ok'], false);
  await f.supervisor.fence(); assert.ok(f.workers.every(w => w.closes > 0));
  assert.equal(f.supervisor.status.run_id, f.m.run_id); assert.equal(f.supervisor.status.run_closed, true);
  const g = fixture(); await g.ready(); await g.supervisor.handle(g.message('ENABLE'));
  g.faults[0]!('process-exited'); await g.supervisor.fence(); assert.ok(g.workers.every(w => w.closes > 0));
});

test('control binding/schema errors disclose no payload and do not mutate prepared state', async () => {
  const f = fixture(); await f.ready();
  for (const [extra, result] of [[{ target_incarnation: 'f'.repeat(32) }, 'WRONG_INCARNATION'],
    [{ run_id: 'f'.repeat(32) }, 'WRONG_RUN'], [{ config_digest: 'f'.repeat(64) }, 'WRONG_CONFIG']] as const) {
    assert.equal((await f.supervisor.handle(f.message('ENABLE', {}, extra)))['result'], result);
  }
  const reply = await f.supervisor.handle(f.message('ENABLE', { secret: 'do-not-reflect' }));
  assert.equal(reply['result'], 'BAD_MESSAGE'); assert.ok(!JSON.stringify(reply).includes('do-not-reflect'));
  assert.equal(f.supervisor.status.state, 'READY'); await f.supervisor.fence();
});

test('reports contain only aggregate verification attempts and no invented measurements/origin evidence', async () => {
  const f = fixture(); await f.ready(); const reply = await f.supervisor.handle(f.message('REPORT'));
  assert.deepEqual(reply['data'], { counters: { verification_attempts: 3 }, measurements: [], same_source_observed: null,
    origin_counts_available: false, worker_verification_attempts: [{ worker_index: 0, attempts: 1 }, { worker_index: 1, attempts: 2 }] });
  await f.supervisor.fence();
});

test('FENCE waits for a delayed factory and closes its late worker without preparing or listening', async () => {
  const gate = deferred(); let prepares = 0, listens = 0, closes = 0;
  const f = fixture('B0');
  const supervisor = new GatewaySupervisor(async () => {
    await gate.promise;
    return { incarnation: '1'.repeat(32), async prepare() { prepares++; }, async enable() {}, async heartbeat() {},
      async listen() { listens++; }, async attempts() { return 0; }, async close() { closes++; } };
  });
  const preparing = supervisor.handle({ ...f.message('PREPARE_RUN', { manifest: f.m, proposed_config_digest: configurationDigest(f.m), role: 'gateway', role_config: {} }),
    target_incarnation: supervisor.incarnation, config_digest: null });
  await turn(); const closing = supervisor.fence(); let settled = false; closing.then(() => { settled = true; });
  await turn(); assert.equal(settled, false); gate.resolve(); await closing; assert.equal((await preparing)['ok'], false);
  assert.equal(prepares, 0); assert.equal(listens, 0); assert.ok(closes > 0);
});

test('a synchronous close failure cannot skip sibling cleanup or strand the cached barrier', async () => {
  const f = fixture(); await f.ready(); f.workers[0]!.close = () => { throw Error('native private detail'); };
  const closing = f.supervisor.fence(); assert.equal(f.supervisor.fence(), closing);
  await assert.rejects(closing, /gateway-fence-failed/); assert.ok(f.workers[1]!.closes > 0);
  assert.equal(f.supervisor.status.run_closed, true);
});

test('a delayed last ENABLE acknowledgement cannot extend the original expiry or start any listener', async () => {
  const f = fixture(); await f.ready(); const gate = deferred(); f.workers[1]!.enable = () => gate.promise;
  const enabling = f.supervisor.handle(f.message('ENABLE')); await turn(); f.advance(3000000000n); gate.resolve();
  assert.equal((await enabling)['ok'], false); assert.ok(f.workers.every(w => w.listens === 0));
  await f.supervisor.fence(); assert.equal(f.supervisor.status.run_closed, true);
});
