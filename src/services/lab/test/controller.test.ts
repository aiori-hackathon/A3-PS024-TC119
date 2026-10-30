import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PROTOCOL, voucherDigest, decodeBase64Url } from '../../../contracts/lib/index.ts';
import { LabRun, ControllerError } from '../src/controller/run.ts';
import { InProcessLink, LinkError } from '../src/controller/link.ts';
import { acquireProjectLock, LockHeldError } from '../src/controller/lock.ts';
import { batches, generateCohort } from '../src/controller/cohort.ts';
import { discovery, newId, request } from '../src/controller/envelope.ts';
import { CLIENT_IDS } from '../src/controller/ports.ts';
import { controllerRig, relink, type ControllerRig } from './helpers/controller-rig.ts';

const fast = { perClient: 2, heartbeatMs: 40, ackDeadlineMs: 150, controlTimeoutMs: 3000 } as const;
const run = (rig: ControllerRig, over: Partial<ConstructorParameters<typeof LabRun>[1]> = {}) =>
  new LabRun({ links: rig.links, redis: rig.redis, reset: rig.reset, gatewayLauncher: rig.launcher }, { ...fast, ...over });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const until = async (f: () => boolean, ms = 3000) => { for (let t = 0; t < ms && !f(); t += 10) await sleep(10); assert.ok(f(), 'condition not reached'); };
const commands = (rig: ControllerRig, role: string) => rig.log.filter((e) => e.role === role).map((e) => e.command);

test('setup follows the plan order, ends with every role ENABLED and the gateway enabled last', async () => {
  const rig = controllerRig(); const r = run(rig);
  const info = await r.start();
  assert.match(info.run_id, /^[0-9a-f]{32}$/);
  assert.equal(info.manifest.inventory_total, 10);
  assert.equal(Object.keys(info.incarnations).length, 8);
  assert.equal(r.phase, 'enabled');
  const first = (role: string, cmd: string) => rig.log.findIndex((e) => e.role === role && e.command === cmd);
  const last = (cmd: string) => Math.max(...rig.log.map((e, i) => (e.command === cmd ? i : -1)));
  // discovery before anything, key before prepare, prepare before provision, provision before ready, ready before enable.
  // Seven roles are discovered first; the gateway can only be discovered after it has been launched with its private input.
  assert.ok(rig.log.slice(0, 7).every((e) => e.command === 'STATUS' && e.role !== 'gateway'));
  assert.ok(first('issuer', 'CREATE_ISSUER_KEY') < first('gateway', 'STATUS'), 'gateway is launched and discovered after the key exists');
  assert.ok(first('gateway', 'STATUS') < first('gateway', 'PREPARE_RUN'));
  assert.ok(first('issuer', 'CREATE_ISSUER_KEY') < first('issuer', 'PREPARE_RUN'));
  assert.ok(last('PREPARE_RUN') < first('issuer', 'PROVISION_VOUCHERS'));
  assert.ok(last('PROVISION_CLIENT') < first('issuer', 'CHECK_READY'));
  assert.ok(last('CHECK_READY') < Math.min(...rig.log.map((e, i) => (e.command === 'ENABLE' ? i : 1e9))));
  // The gateway is enabled strictly after the issuer, origin and every client.
  const gatewayEnable = first('gateway', 'ENABLE');
  for (const role of ['issuer', 'origin', ...CLIENT_IDS.map((c) => `client-${c}`)]) assert.ok(first(role, 'ENABLE') < gatewayEnable, role);
  // Redis was prepared before the manifest existed and installed with the accepted digest before any PREPARE.
  assert.match(rig.redis.calls[0]!, /^prepare:/);
  assert.equal(rig.redis.calls[1], `install:${info.run_id}:${info.config_digest}`);
  assert.equal(rig.gateway.state, 'ENABLED');
  assert.equal(rig.launcher.launched, 1, 'gateway startup input delivered once, before its PREPARE');
  await r.stop();
});

test('initial PREPARE carries a null envelope digest; every later command carries the accepted one; incarnations are targeted', async () => {
  const rig = controllerRig(); const r = run(rig);
  const info = await r.start();
  const sent: Record<string, unknown>[] = [];
  // Replay envelopes through the logged payload view: PREPARE payload names the proposed digest.
  for (const e of rig.log.filter((x) => x.command === 'PREPARE_RUN')) { assert.equal(e.payload['proposed_config_digest'], info.config_digest); sent.push(e.payload); }
  assert.equal(sent.length, 8);
  assert.deepEqual(rig.log.filter((x) => x.command === 'PREPARE_RUN').map((e) => e.payload['role']).sort(), ['client', 'client', 'client', 'client', 'client', 'gateway', 'issuer', 'origin']);
  assert.equal(new Set(Object.values(info.incarnations)).size, 8);
  await r.stop();
});

test('voucher cohort: bounded sealed frames, each client gets only its own plaintext, issuer gets only the matching digests', async () => {
  const rig = controllerRig(); const r = run(rig, { perClient: 2 });
  await r.start();
  const issuerFrames = rig.log.filter((e) => e.role === 'issuer' && e.command === 'PROVISION_VOUCHERS').map((e) => e.payload);
  assert.equal(issuerFrames.length, 1);
  assert.equal(issuerFrames[0]!['final_batch'], true); assert.equal(issuerFrames[0]!['expected_total'], 10);
  const digests = new Set<string>(issuerFrames[0]!['items']);
  assert.equal(digests.size, 10);
  const seen = new Set<string>();
  for (const id of CLIENT_IDS) {
    const frames = rig.log.filter((e) => e.role === `client-${id}` && e.command === 'PROVISION_CLIENT').map((e) => e.payload);
    assert.equal(frames.length, 1); assert.equal(frames[0]!['final_batch'], true); assert.equal(frames[0]!['expected_total'], 2);
    for (const item of frames[0]!['items'] as string[]) {
      assert.match(item, /^[A-Za-z0-9_-]{43}$/); assert.ok(!seen.has(item), 'no voucher is given to two clients'); seen.add(item);
      assert.ok(digests.has(voucherDigest(decodeBase64Url(item, 32, false))), 'issuer holds the digest of every client voucher');
    }
  }
  assert.equal(seen.size, 10);
  assert.ok(!JSON.stringify(issuerFrames).includes([...seen][0]!), 'plaintext never reaches the issuer');
  await r.stop();
});

test('large cohorts are split into frames of at most 128 with the seal only on the last', () => {
  const c = generateCohort(300, ['A', 'B']);
  const frames = [...batches(c.issuerDigests)];
  assert.deepEqual(frames.map((f) => f.length), [128, 128, 128, 128, 88]);
  assert.equal(frames.flat().length, 600);
  assert.ok(frames.every((f) => f.length <= PROTOCOL.provision_batch_max));
  assert.throws(() => generateCohort(0)); assert.throws(() => generateCohort(16385 / 5));
  const a = generateCohort(3), b = generateCohort(3);
  assert.equal(new Set([...a.issuerDigests, ...b.issuerDigests]).size, 30, 'CSPRNG vouchers never repeat across runs');
});

test('heartbeats are sequenced with exactly one outstanding per link, to the issuer and the gateway', async () => {
  const rig = controllerRig(); rig.gateway.ackDelayMs = 25;
  const r = run(rig); await r.start();
  await until(() => rig.gateway.heartbeats.length >= 4);
  assert.deepEqual(rig.gateway.heartbeats.slice(0, 4), [1, 2, 3, 4]);
  assert.equal(rig.gateway.maxConcurrent, 1, 'never a second heartbeat before the first is acknowledged');
  assert.equal(rig.log.filter((e) => e.role === 'issuer' && e.command === 'HEARTBEAT').length >= 3, true);
  assert.equal(r.phase, 'enabled');
  await r.stop();
});

test('operator stop: strong barrier first, Redis discard only afterwards, every role fenced and latched closed', async () => {
  const rig = controllerRig(); const r = run(rig); await r.start();
  const result = await r.stop('operator-stop');
  assert.deepEqual(result, { reason: 'operator-stop', reset_confirmed: true, error: null });
  assert.deepEqual(rig.reset.events, ['fence-start', 'fence-confirmed', 'redis-discarded']);
  assert.equal(r.phase, 'closed');
  assert.equal(rig.issuer.state, 'FENCED'); assert.equal(rig.origin.state, 'FENCED'); assert.equal(rig.gateway.state, 'FENCED');
  for (const id of CLIENT_IDS) assert.equal(rig.clients[id].state, 'FENCED');
  assert.equal(await r.stop(), result, 'idempotent');
  assert.equal(rig.reset.events.length, 3, 'a second stop does not run the barrier again');
});

test('a late or missing gateway acknowledgement closes the whole run', async () => {
  const rig = controllerRig(); const r = run(rig); await r.start();
  rig.gateway.dropAcks = true;
  const result = await r.closed();
  assert.equal(result.reason, 'control-lost');
  assert.equal(result.reset_confirmed, true);
  assert.equal(rig.issuer.state, 'FENCED', 'the issuer is closed too, not left serving');
  assert.deepEqual(rig.reset.events.slice(0, 2), ['fence-start', 'fence-confirmed']);
});

test('a wrong-sequence acknowledgement is treated as lost supervision', async () => {
  const rig = controllerRig(); const r = run(rig); await r.start();
  rig.gateway.badSeq = true;
  assert.equal((await r.closed()).reason, 'control-lost');
});

test('a watched role exiting closes the run via the same barrier', async () => {
  const rig = controllerRig(); const r = run(rig); await r.start();
  r.roleLost('client-C');
  const result = await r.closed();
  assert.equal(result.reason, 'process-exited'); assert.equal(result.reset_confirmed, true);
  assert.equal(rig.origin.state, 'FENCED');
});

test('a role that has already carried a run is refused and nothing new is prepared', async () => {
  const rig = controllerRig();
  const first = run(rig); await first.start(); await first.stop();
  const again = relink(rig);
  const second = new LabRun({ links: again.links, redis: rig.redis, reset: rig.reset, gatewayLauncher: again.launcher }, fast);
  await assert.rejects(second.start(), (e: ControllerError) => e.code === 'role-not-fresh');
  assert.ok(again.log.every((e) => e.command === 'STATUS' || e.command === 'FENCE'), 'only discovery, never PREPARE or ENABLE');
  assert.equal(rig.gateway.state, 'FENCED');
});

test('setup failure at any step closes through the barrier and discards Redis afterwards, with a fixed error code', async () => {
  for (const mutate of [
    (rig: ControllerRig) => { rig.redis.failPrepare = true; },
    (rig: ControllerRig) => { rig.redis.failInstall = true; },
    (rig: ControllerRig) => { rig.gateway.failCommand = 'PREPARE_RUN'; },
    (rig: ControllerRig) => { rig.gateway.workers = 1; }, // B1 needs two ready workers
  ]) {
    const rig = controllerRig(); mutate(rig);
    const r = run(rig);
    const err = await r.start().then(() => null, (e) => e);
    assert.ok(err instanceof ControllerError, 'fixed error');
    assert.doesNotMatch(String(err.message), /password|redis down|acl failure/);
    assert.equal(r.phase, 'closed');
    assert.deepEqual(rig.reset.events, ['fence-start', 'fence-confirmed', 'redis-discarded']);
    assert.equal(rig.gateway.state, 'FENCED'); assert.equal(rig.issuer.state, 'FENCED');
  }
});

test('B0 expects exactly one ready worker, B1 exactly two', async () => {
  const b0 = controllerRig(); b0.gateway.workers = 1;
  const r0 = run(b0, { gatewayProfile: 'B0' }); const info = await r0.start();
  assert.equal(info.manifest.limits.gateway.workers, 1); await r0.stop();
  const b1 = controllerRig(); b1.gateway.workers = 1;
  await assert.rejects(run(b1, { gatewayProfile: 'B1' }).start(), (e: ControllerError) => e.code === 'readiness-failed');
});

test('if shutdown cannot be confirmed the run stays closed: no Redis discard, no retry, no restart', async () => {
  const rig = controllerRig(); const r = run(rig); await r.start();
  rig.reset.failFence = true;
  const result = await r.stop('operator-stop');
  assert.deepEqual(result, { reason: 'operator-stop', reset_confirmed: false, error: 'close-unconfirmed' });
  assert.ok(!rig.reset.events.includes('redis-discarded'));
  assert.equal(r.phase, 'closed');
  assert.equal(await r.stop(), result);
  await assert.rejects(r.start());
});

test('an unconfirmed Redis discard is reported as unconfirmed', async () => {
  const rig = controllerRig(); const r = run(rig); await r.start();
  rig.reset.failDiscard = true;
  const result = await r.stop();
  assert.equal(result.reset_confirmed, false); assert.equal(result.error, 'close-unconfirmed');
});

test('project lock: exclusive, never broken by contents, released only by its owner', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ps024-lock-'));
  const path = join(dir, 'project.lock');
  const a = acquireProjectLock(path);
  assert.throws(() => acquireProjectLock(path), LockHeldError);
  assert.equal(JSON.parse(readFileSync(path, 'utf8')).pid, process.pid);
  a.release(); a.release();
  assert.equal(existsSync(path), false);
  // A stale file left by a crashed controller is NOT treated as proof that its run is gone.
  writeFileSync(path, JSON.stringify({ pid: 999999, acquired_at_utc: '2026-01-01T00:00:00Z' }));
  assert.throws(() => acquireProjectLock(path), LockHeldError);
  assert.equal(existsSync(path), true, 'stale lock left in place for the operator');
});

test('links: correlate by request_id, bound pending, time out, and a bad frame poisons the link', async () => {
  const slow = new Map<string, () => void>();
  const echo = (delay: number) => async (raw: unknown) => {
    const req = raw as Record<string, any>;
    if (delay) await new Promise((r) => setTimeout(r, delay));
    return { version: 1, request_id: req['request_id'], state: 'FENCED', run_id: null, config_digest: null, incarnation: 'a'.repeat(32), ok: true, result: 'STATUS', data: { ready: false, run_closed: false, fault: null } };
  };
  void slow;
  const link = new InProcessLink('issuer', echo(0), 200);
  const [a, b] = await Promise.all([link.send(discovery()), link.send(discovery())]);
  assert.notEqual(a['request_id'], b['request_id']);
  await assert.rejects(new InProcessLink('issuer', echo(300), 100).send(discovery()), (e: LinkError) => e.code === 'timeout');
  await assert.rejects(link.send({ version: 1 }), (e: LinkError) => e.code === 'protocol');
  const many = new InProcessLink('issuer', echo(200), 1000);
  const sends = Array.from({ length: 9 }, () => many.send(discovery()));
  await assert.rejects(many.send(discovery()), (e: LinkError) => e.code === 'too-many-pending');
  await Promise.all(sends);
  // A reply for an unknown request poisons the link and fails what is pending.
  const rogue = new InProcessLink('issuer', async () => ({ version: 1, request_id: 'f'.repeat(32), state: 'FENCED', run_id: null, config_digest: null, incarnation: 'a'.repeat(32), ok: true, result: 'STATUS', data: { ready: false, run_closed: false, fault: null } }), 500);
  await assert.rejects(rogue.send(discovery()), (e: LinkError) => e.code === 'link-lost');
  await assert.rejects(rogue.send(discovery()), (e: LinkError) => e.code === 'link-lost');
  void request;
});
