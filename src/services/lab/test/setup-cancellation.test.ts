// Phase C gate: a close that arrives while ANY setup step is pending must win. Delayed callbacks from the old setup can
// neither mutate a role nor enable a service after the reset has begun, and the close path is published once.
import test from 'node:test';
import assert from 'node:assert/strict';
import { LabRun, ControllerError } from '../src/controller/run.ts';
import type { Json, RoleLink, RoleName } from '../src/controller/ports.ts';
import { controllerRig, type ControllerRig } from './helpers/controller-rig.ts';

const fast = { perClient: 2, heartbeatMs: 40, ackDeadlineMs: 150, controlTimeoutMs: 3000, setupDrainMs: 2000 } as const;
const MUTATING = new Set(['CREATE_ISSUER_KEY', 'PREPARE_RUN', 'PROVISION_VOUCHERS', 'PROVISION_CLIENT', 'CHECK_READY', 'ENABLE']);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const until = async (f: () => boolean, ms = 3000) => { for (let t = 0; t < ms && !f(); t += 5) await sleep(5); assert.ok(f(), 'condition not reached'); };

/** Holds the first matching request on a link until released, then forwards it. */
class HoldLink implements RoleLink {
  readonly role: RoleName; readonly inner: RoleLink;
  reached = false; #release!: () => void; readonly released = new Promise<void>((r) => { this.#release = r; });
  readonly #match: (req: Json) => boolean;
  constructor(inner: RoleLink, match: (req: Json) => boolean) { this.inner = inner; this.role = inner.role; this.#match = match; }
  release(): void { this.#release(); }
  async send(request: Json, timeoutMs?: number): Promise<Json> {
    if (!this.reached && this.#match(request)) { this.reached = true; await this.released; }
    return this.inner.send(request, timeoutMs);
  }
  close(): void { this.inner.close(); }
}
const swap = (rig: ControllerRig, which: 'issuer' | 'origin' | 'client-A', match: (r: Json) => boolean) => {
  const hold = new HoldLink(which === 'issuer' ? rig.links.issuer : which === 'origin' ? rig.links.origin : rig.links.clients.A, match);
  if (which === 'issuer') rig.links.issuer = hold; else if (which === 'origin') rig.links.origin = hold; else rig.links.clients.A = hold;
  return hold;
};
const mk = (rig: ControllerRig) => new LabRun({ links: rig.links, redis: rig.redis, reset: rig.reset, gatewayLauncher: rig.launcher }, fast);

/** Everything the controller sent to roles AFTER the close request must be non-mutating (the barrier uses its own links). */
function assertNothingMutatedAfter(rig: ControllerRig, mark: number, label: string, inFlight?: string) {
  const late = rig.log.slice(mark).filter((e) => MUTATING.has(e.command));
  // The one request that was already in flight when the close arrived is forwarded when the hold is released; it is the
  // only mutating request permitted, and nothing may be sent after it.
  if (inFlight) { const i = late.findIndex((e) => `${e.role}:${e.command}` === inFlight); if (i >= 0) late.splice(i, 1); }
  assert.deepEqual(late.map((e) => `${e.role}:${e.command}`), [], `${label}: no mutating command may follow the close request`);
}
function assertClosedCleanly(rig: ControllerRig, r: LabRun, label: string) {
  assert.equal(r.phase, 'closed', label);
  assert.deepEqual(rig.reset.events, ['fence-start', 'fence-confirmed', 'redis-discarded'], `${label}: one barrier, then one discard`);
  assert.equal(rig.issuer.state, 'FENCED', label); assert.equal(rig.origin.state, 'FENCED', label);
  assert.notEqual(rig.gateway.state, 'ENABLED', label);
}

const roleStages: [string, 'issuer' | 'origin' | 'client-A', (r: Json) => boolean][] = [
  ['issuer key creation', 'issuer', (r) => r['command'] === 'CREATE_ISSUER_KEY'],
  ['origin PREPARE', 'origin', (r) => r['command'] === 'PREPARE_RUN'],
  ['issuer PREPARE', 'issuer', (r) => r['command'] === 'PREPARE_RUN'],
  ['client provisioning', 'client-A', (r) => r['command'] === 'PROVISION_CLIENT'],
  ['issuer provisioning', 'issuer', (r) => r['command'] === 'PROVISION_VOUCHERS'],
  ['readiness', 'origin', (r) => r['command'] === 'CHECK_READY'],
  ['origin ENABLE', 'origin', (r) => r['command'] === 'ENABLE'],
  ['issuer ENABLE', 'issuer', (r) => r['command'] === 'ENABLE'],
];
for (const [name, which, match] of roleStages) {
  test(`close while the "${name}" step is pending: the late reply cannot lead to any further mutation or ENABLE`, async () => {
    const rig = controllerRig(); const hold = swap(rig, which, match); const r = mk(rig);
    const started = r.start().then(() => 'started', (e) => e);
    await until(() => hold.reached);
    const mark = rig.log.length;
    const closing = r.stop('operator-stop');
    await sleep(30);
    hold.release();
    const outcome = await started;
    const result = await closing;
    assert.ok(outcome instanceof ControllerError, `${name}: start() must fail, got ${String(outcome)}`);
    assert.equal(result.reset_confirmed, true);
    assertNothingMutatedAfter(rig, mark, name, `${which}:${name.includes('key') ? 'CREATE_ISSUER_KEY' : name.includes('PREPARE') ? 'PREPARE_RUN' : name.includes('provisioning') ? (which === 'issuer' ? 'PROVISION_VOUCHERS' : 'PROVISION_CLIENT') : name === 'readiness' ? 'CHECK_READY' : 'ENABLE'}`);
    assertClosedCleanly(rig, r, name);
  });
}

test('close while the replay-store preparation is pending: its late result is discarded and nothing proceeds', async () => {
  const rig = controllerRig(); let release!: () => void; const gate = new Promise<void>((r) => { release = r; });
  const real = rig.redis.prepare.bind(rig.redis); let reached = false;
  rig.redis.prepare = async (id: string) => { reached = true; await gate; return real(id); };
  const r = mk(rig); const started = r.start().then(() => 'started', (e) => e);
  await until(() => reached);
  const mark = rig.log.length; const closing = r.stop('operator-stop');
  release();
  assert.ok((await started) instanceof ControllerError); await closing;
  assert.deepEqual(rig.redis.calls.filter((c) => c.startsWith('install')), [], 'policy was never installed after the close');
  assertNothingMutatedAfter(rig, mark, 'redis prepare'); assertClosedCleanly(rig, r, 'redis prepare');
  assert.equal(rig.launcher.launched, 0, 'the gateway was never launched');
});

test('close while the replay-store install is pending: the gateway is never launched or prepared', async () => {
  const rig = controllerRig(); let release!: () => void; const gate = new Promise<void>((r) => { release = r; });
  const real = rig.redis.install.bind(rig.redis); let reached = false;
  rig.redis.install = async (m, d) => { reached = true; await gate; return real(m, d); };
  const r = mk(rig); const started = r.start().then(() => 'started', (e) => e);
  await until(() => reached);
  const mark = rig.log.length; const closing = r.stop('operator-stop');
  release();
  assert.ok((await started) instanceof ControllerError); await closing;
  assert.equal(rig.launcher.launched, 0);
  assert.equal(rig.log.filter((e) => e.role === 'gateway').length, 0, 'no command ever reached the gateway');
  assertNothingMutatedAfter(rig, mark, 'redis install'); assertClosedCleanly(rig, r, 'redis install');
});

test('a gateway launch that completes AFTER close is discarded: its link is closed and it is never discovered, prepared or enabled', async () => {
  const rig = controllerRig(); let release!: () => void; rig.launcher.hold = new Promise<void>((r) => { release = r; });
  const r = mk(rig); const started = r.start().then(() => 'started', (e) => e);
  await until(() => rig.redis.calls.some((c) => c.startsWith('install')));
  await sleep(20);
  const mark = rig.log.length; const closing = r.stop('operator-stop');
  await sleep(30);
  release(); // late launcher completion
  assert.ok((await started) instanceof ControllerError); await closing;
  assert.equal(rig.log.filter((e) => e.role === 'gateway').length, 0, 'the late gateway is never spoken to by setup');
  assertNothingMutatedAfter(rig, mark, 'late launch');
  assert.equal(r.phase, 'closed');
  assert.equal(rig.gateway.state, 'FENCED');
  assert.equal(rig.reset.events.filter((e) => e === 'redis-discarded').length, 1);
});

test('a close request that never gets its in-flight step back still runs the barrier after the bounded drain', async () => {
  const rig = controllerRig(); const hold = swap(rig, 'origin', (q) => q['command'] === 'PREPARE_RUN'); // never released
  const r = new LabRun({ links: rig.links, redis: rig.redis, reset: rig.reset, gatewayLauncher: rig.launcher }, { ...fast, setupDrainMs: 100, controlTimeoutMs: 60_000 });
  void r.start().catch(() => undefined);
  await until(() => hold.reached);
  const result = await r.stop('operator-stop');
  assert.equal(result.reset_confirmed, true);
  assertClosedCleanly(rig, r, 'stuck step');
});

test('close is published once, synchronously: a reentrant close from inside the barrier shares the same promise and the barrier runs once', async () => {
  const rig = controllerRig(); const r = mk(rig); await r.start();
  const realFence = rig.reset.fenceAll.bind(rig.reset); let inner: Promise<unknown> | null = null;
  rig.reset.fenceAll = async () => { inner = r.stop('reentrant'); return realFence(); };
  const first = r.stop('operator-stop');
  const result = await first;
  assert.strictEqual(await inner, result, 'the reentrant call got the very same result');
  assert.equal(result.reason, 'operator-stop');
  assert.equal(rig.reset.events.filter((e) => e === 'fence-start').length, 1);
});

test('a link whose close() throws does not stop the other links from being closed', async () => {
  const rig = controllerRig(); const r = mk(rig); await r.start();
  const closed: string[] = [];
  for (const [name, link] of [['issuer', rig.links.issuer], ['origin', rig.links.origin], ['client-A', rig.links.clients.A]] as const) {
    const original = link.close.bind(link);
    link.close = () => { closed.push(name); original(); if (name === 'issuer') throw new Error('close failed'); };
  }
  const result = await r.stop('operator-stop');
  assert.equal(result.reset_confirmed, true);
  assert.deepEqual(closed.sort(), ['client-A', 'issuer', 'origin']);
  assert.equal(r.phase, 'closed');
});

test('a close racing the final ENABLE leaves no ENABLED issuer: the barrier fences it and heartbeats stop', async () => {
  const rig = controllerRig(); const hold = swap(rig, 'issuer', (q) => q['command'] === 'ENABLE');
  const r = mk(rig); const started = r.start().then(() => 'started', (e) => e);
  await until(() => hold.reached);
  const closing = r.stop('operator-stop'); await sleep(20); hold.release();
  await started; await closing;
  assert.equal(rig.issuer.state, 'FENCED');
  const beats = rig.log.filter((e) => e.command === 'HEARTBEAT').length;
  await sleep(150);
  assert.equal(rig.log.filter((e) => e.command === 'HEARTBEAT').length, beats, 'no heartbeats after the run is closed');
});
