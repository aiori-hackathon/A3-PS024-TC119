import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import golden from '../../../contracts/fixtures/policy-golden.json' with { type: 'json' };
import { configurationDigest, validateManifest } from '../../../contracts/lib/index.ts';
import { WorkerLease, type LeaseRuntime, type WorkerCloseReason, type WorkerLeaseGrant } from '../src/worker-lease.ts';

const base = 10000000000n, second = 1000000000n;
const manifest = validateManifest(golden.manifest);
const binding = { worker_incarnation: '1'.repeat(32), supervisor_incarnation: '2'.repeat(32) };
function grant(issued = base, sequence = 0): WorkerLeaseGrant {
  return { version: 1, run_id: manifest.run_id, config_digest: configurationDigest(manifest), ...binding,
    sequence, issued_at_ns: String(issued), expires_at_ns: String(issued + 3n * second) };
}
function fixture() {
  const clock = { now: base };
  const timers: { callback: () => void; afterMs: number; canceled: boolean }[] = [];
  const reasons: WorkerCloseReason[] = [];
  const runtime: LeaseRuntime = {
    nowNs: () => clock.now,
    schedule(afterMs, callback) {
      const timer = { callback, afterMs, canceled: false }; timers.push(timer);
      return () => { timer.canceled = true; };
    },
  };
  const lease = WorkerLease.prepare(manifest, binding, reason => { reasons.push(reason); }, runtime);
  return { lease, clock, timers, reasons, runtime };
}
function active() {
  const f = fixture(); assert.equal(f.lease.markReady(), true); assert.equal(f.lease.enable(grant()), true); return f;
}

test('prepared/ready stages do not admit work; first ENABLE installs the sole initial lease', () => {
  const { lease, timers } = fixture();
  assert.equal(lease.status.state, 'PREPARED'); assert.equal(lease.checkActive(), false);
  assert.equal(lease.enable(grant()), false); assert.equal(lease.heartbeat(grant(base, 1)), false);
  assert.equal(lease.markReady(), true); assert.equal(lease.markReady(), true);
  assert.equal(timers.length, 0); assert.equal(lease.checkActive(), false);
  assert.equal(lease.enable(grant()), true); assert.equal(lease.status.state, 'ENABLED');
  assert.equal(lease.markReady(), false); assert.equal(lease.checkActive(), true);
  assert.equal(timers[0]!.afterMs, 3000); lease.fence();
});

test('delayed initial ENABLE retains original expiry and gets no fresh duration on receipt', () => {
  const { lease, clock, timers } = fixture(); lease.markReady(); clock.now += 2n * second;
  assert.equal(lease.enable(grant()), true); assert.equal(timers[0]!.afterMs, 1000);
  clock.now = base + 3n * second;
  assert.equal(lease.checkActive(), false); assert.equal(lease.status.fault, 'lease-expired');
});

test('repeated ENABLE acknowledges only the original grant and never refreshes expiry', () => {
  const { lease, clock, timers } = active(); clock.now += 2n * second;
  assert.equal(lease.enable(grant()), true); assert.equal(timers.length, 1);
  assert.equal(lease.enable(grant(clock.now)), false); assert.equal(timers.length, 1);
  clock.now = base + 3n * second;
  assert.equal(lease.enable(grant(clock.now)), false); assert.equal(lease.status.run_closed, true);
});

test('renewal preserves supervisor deadline and canceled/early timers evaluate the current grant', () => {
  const { lease, clock, timers, reasons } = active(); const original = timers[0]!;
  clock.now += second;
  assert.equal(lease.heartbeat(grant(clock.now, 1)), true); assert.equal(original.canceled, true);
  clock.now = base + 3n * second;
  original.callback(); // Deliberately deliver an obsolete timer after the OLD expiry.
  assert.equal(lease.checkActive(), true); assert.deepEqual(reasons, []);
  assert.equal(timers.at(-1)!.afterMs, 1000);
  assert.equal(lease.enable(grant()), true); // Repeated ENABLE does not inspect the old grant as a renewal.
  clock.now = base + 4n * second; timers.at(-1)!.callback();
  assert.equal(lease.status.fault, 'lease-expired'); assert.deepEqual(reasons, ['lease-expired']);
});

test('expiry wins over a fresh heartbeat even when the timer callback has not run', () => {
  const { lease, clock, reasons } = active(); clock.now += 3n * second;
  assert.equal(lease.heartbeat(grant(clock.now, 1)), false);
  assert.equal(lease.status.state, 'FAULTED'); assert.equal(lease.signal.aborted, true);
  assert.equal(lease.enable(grant()), false); assert.equal(lease.markReady(), false);
  lease.fence(); assert.equal(lease.status.state, 'FAULTED');
  assert.deepEqual(reasons, ['lease-expired']);
});

test('processing that crosses existing expiry cannot renew after an earlier active check', () => {
  const { lease, clock } = active(); clock.now += 2n * second;
  const incoming = grant(clock.now, 1);
  Object.defineProperty(incoming, 'sequence', { enumerable: true, get() { clock.now = base + 3n * second; return 1; } });
  assert.equal(lease.heartbeat(incoming), false); assert.equal(lease.status.fault, 'lease-expired');
});

test('duplicate/out-of-order sequences and older issuance cannot extend an active lease', () => {
  const { lease, clock, timers } = active(); clock.now += second;
  assert.equal(lease.heartbeat(grant(clock.now, 2)), true); const count = timers.length;
  clock.now += second;
  for (const g of [grant(clock.now, 2), grant(clock.now, 1), grant(base, 3)]) assert.equal(lease.heartbeat(g), false);
  assert.equal(timers.length, count);
  clock.now = base + 4n * second; assert.equal(lease.checkActive(), false);
});

test('run/config/incarnation binding and exact bounded canonical nanoseconds are mandatory', () => {
  const { lease, clock, timers } = active(); clock.now += second;
  const valid = grant(clock.now, 1);
  const bad: unknown[] = [null, true, {}, { ...valid, extra: 1 }];
  for (const field of ['run_id', 'config_digest', 'worker_incarnation', 'supervisor_incarnation'] as const) bad.push({ ...valid, [field]: 'f'.repeat(field === 'config_digest' ? 64 : 32) });
  for (const value of ['', '-1', '+1', '01', '1e9', '1.0', ' 1', '9'.repeat(21), '18446744073709551616', 10000000000]) bad.push({ ...valid, issued_at_ns: value });
  bad.push({ ...valid, version: 2 }, { ...valid, sequence: -0 }, { ...valid, sequence: 0.5 }, { ...valid, sequence: Number.MAX_SAFE_INTEGER + 1 },
    { ...valid, expires_at_ns: String(clock.now + 4n * second) }, grant(clock.now + second, 1));
  for (const raw of bad) assert.equal(lease.heartbeat(raw), false);
  assert.equal(timers.length, 1); assert.equal(lease.checkActive(), true); lease.fence();
});

test('expired first grant closes the run and local FENCE never acknowledges completed quiescence', () => {
  const f = fixture(); f.lease.markReady(); f.clock.now += 3n * second;
  assert.equal(f.lease.enable(grant()), false); assert.equal(f.lease.status.run_closed, true);
  const g = active(); g.lease.fence(); g.lease.fence();
  assert.equal(g.lease.status.state, 'CLOSING'); assert.equal(g.lease.status.run_closed, true);
  assert.equal(g.lease.enable(grant()), false); assert.deepEqual(g.reasons, ['operator-stop']);
  assert.equal(g.lease.signal.aborted, true);
});

test('terminal cancellation precedes observer callbacks and reentrant attempts cannot reopen the run', () => {
  const f = fixture(); let lease: WorkerLease; const seen: boolean[] = [];
  lease = WorkerLease.prepare(manifest, binding, () => { seen.push(lease.status.run_closed, lease.signal.aborted); throw Error('private observer detail'); }, f.runtime);
  lease.markReady(); lease.enable(grant());
  lease.signal.addEventListener('abort', () => { seen.push(!lease.enable(grant()), !lease.checkActive()); });
  lease.requestClose('dependency-lost'); lease.requestClose('control-lost');
  assert.deepEqual(seen, [true, true, true, true]); assert.equal(lease.status.fault, 'dependency-lost');
});

test('regressing/throwing/invalid monotonic clocks close access without renewing', () => {
  for (const value of [base - 1n, -1n, 1n << 64n]) {
    const { lease, clock } = active(); clock.now = value;
    assert.equal(lease.checkActive(), false); assert.equal(lease.status.fault, 'clock-unsafe');
  }
  const f = active(); f.runtime.nowNs = () => { throw Error('private clock detail'); };
  assert.equal(f.lease.heartbeat(grant(base + second, 1)), false); assert.equal(f.lease.status.fault, 'clock-unsafe');
});

test('scheduler/cleanup failures cannot leave an enabled lease or skip closure notification', () => {
  const f = fixture(); f.runtime.schedule = () => { throw Error('private scheduler detail'); };
  f.lease.markReady(); assert.equal(f.lease.enable(grant()), false);
  assert.equal(f.lease.status.state, 'FAULTED'); assert.deepEqual(f.reasons, ['unsafe-state']);
  const g = fixture(); g.runtime.schedule = () => () => { throw Error('private cancel detail'); };
  g.lease.markReady(); g.lease.enable(grant()); g.lease.fence();
  assert.deepEqual(g.reasons, ['operator-stop']); assert.equal(g.lease.status.state, 'CLOSING');
});

test('configuration and identity are copied; status exposes no mutable clock or credential material', () => {
  const config = structuredClone(manifest), ids = { ...binding }, f = fixture();
  const lease = WorkerLease.prepare(config, ids, () => {}, f.runtime);
  config.run_id = 'f'.repeat(32); ids.worker_incarnation = 'f'.repeat(32);
  lease.markReady(); assert.equal(lease.enable(grant()), true);
  assert.equal(Object.isFrozen(lease.status), true);
  assert.deepEqual(Object.keys(lease.status).sort(), ['config_digest', 'fault', 'incarnation', 'run_closed', 'run_id', 'state']);
  lease.fence();
  assert.throws(() => WorkerLease.prepare(null, binding, () => {}), /worker-configuration-invalid/);
  assert.throws(() => WorkerLease.prepare(manifest, { ...binding, worker_incarnation: 'invalid' }, () => {}), /worker-configuration-invalid/);
});

test('real monotonic timer closes an idle enabled run without a request or heartbeat', async () => {
  const reasons: WorkerCloseReason[] = [];
  const lease = WorkerLease.prepare(manifest, binding, reason => { reasons.push(reason); }); lease.markReady();
  assert.equal(lease.enable(grant(process.hrtime.bigint())), true);
  await delay(3100);
  // Read status BEFORE calling checkActive: this assertion requires the actual timer path.
  assert.equal(lease.status.run_closed, true); assert.deepEqual(reasons, ['lease-expired']);
});
