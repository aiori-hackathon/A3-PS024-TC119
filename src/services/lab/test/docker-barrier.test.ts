import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { request as httpRequest } from 'node:http';
import type { ChildProcess } from 'node:child_process';
import { configurationDigest, hex, makeManifest, validateControlResponse } from '../../../contracts/lib/index.ts';
import { DockerAdapters, DockerProject, SERVICE_FOR_ROLE, type DockerCli, type RunResult, type Target } from '../src/controller/docker.ts';
import { PartialResetBarrier } from '../src/controller/partial-barrier.ts';
import { InProcessLink } from '../src/controller/link.ts';
import type { Json, RoleLink, RoleName } from '../src/controller/ports.ts';
import { OriginRole } from '../src/origin/control.ts';

type Mode = 'ok' | 'daemon-down' | 'permission' | 'timeout' | 'garbled' | 'wrong-id' | 'empty' | 'inspect-error';
/** Minimal Docker daemon: containers by 64-hex ID, with ways for inspection to fail that must never read as "gone". */
class FakeDocker implements DockerCli {
  containers = new Map<string, { running: boolean; service: string }>();
  stubborn = new Set<string>(); sticky = new Set<string>(); calls: string[] = [];
  absentWording: 'cli' | 'daemon' = 'daemon';
  mode: Mode = 'ok'; modeFor: Set<string> | null = null; removals = 0;
  add(service: string): string { const id = hex(randomBytes(32)); this.containers.set(id, { running: true, service }); return id; }
  async run(args: string[]): Promise<RunResult> {
    this.calls.push(args.join(' '));
    const ok = (stdout = ''): RunResult => ({ status: 0, stdout, stderr: '', timedOut: false, failed: false });
    const err = (stderr: string, status = 1): RunResult => ({ status, stdout: '', stderr, timedOut: false, failed: false });
    if (args[0] === 'compose') {
      const svc = args.at(-1)!;
      const found = [...this.containers].filter(([, c]) => c.service === svc);
      return ok(found.map(([id]) => id).join('\n') + (found.length ? '\n' : ''));
    }
    const id = args.at(-1)!;
    if (args[0] === 'inspect') {
      const faulty = this.mode !== 'ok' && (!this.modeFor || this.modeFor.has(id));
      if (faulty) {
        switch (this.mode) {
          case 'daemon-down': return err('Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?');
          case 'permission': return err('permission denied while trying to connect to the Docker daemon socket');
          case 'timeout': return { status: null, stdout: '', stderr: '', timedOut: true, failed: true };
          case 'garbled': return ok('this is not an inspect answer');
          case 'empty': return ok('');
          case 'wrong-id': return ok(`${hex(randomBytes(32))} false exited`);
          case 'inspect-error': return err('Error response from daemon: something unexpected happened');
        }
      }
      const c = this.containers.get(id);
      if (!c) return err(this.absentWording === 'cli' ? `error: no such object: ${id}\n` : `Error response from daemon: No such object: ${id}`);
      return ok(args.includes('{{.Id}}') ? id : `${id} ${c.running} ${c.running ? 'running' : 'exited'}`);
    }
    if (args[0] === 'kill') { const c = this.containers.get(id); if (c && !this.stubborn.has(id)) c.running = false; return ok(); }
    if (args[0] === 'rm') { this.removals++; if (!this.sticky.has(id)) this.containers.delete(id); return ok(); }
    return ok();
  }
  spawn(): ChildProcess { throw new Error('not used'); }
}
const noSleep = () => Promise.resolve();
const fast = { sleep: noSleep, confirmMs: 40, killRetryMs: 5 };
const signal = () => new AbortController().signal;

test('container identity is the immutable 64-hex ID; absent or malformed is an error, never a name', async () => {
  const d = new FakeDocker(); const id = d.add('issuer');
  const p = new DockerProject(d, 'compose.yaml');
  assert.deepEqual(await p.instance('issuer'), { role: 'issuer', container_id: id });
  await assert.rejects(p.instance('gateway'), /instance-unavailable/);
  d.add('redis');
  assert.match(await p.redisInstance(), /^[0-9a-f]{64}$/);
  assert.equal(SERVICE_FOR_ROLE['client-C'], 'client-c');
  d.add('issuer'); // two containers for one role is ambiguous identity, not "pick one"
  await assert.rejects(p.instance('issuer'), /instance-unavailable/);
});

test('instance state: running and stopped need a well-formed answer for THAT id; absence needs the daemon to say so', async () => {
  const d = new FakeDocker(); const id = d.add('issuer'); const p = new DockerProject(d, 'c.yaml');
  assert.equal(await p.state(id), 'running');
  d.containers.get(id)!.running = false;
  assert.equal(await p.state(id), 'stopped');
  d.containers.delete(id);
  assert.equal(await p.state(id), 'absent');
  d.absentWording = 'cli'; // the wording the current docker CLI actually prints
  assert.equal(await p.state(id), 'absent');
  d.absentWording = 'daemon';
  assert.equal(await p.state('not-a-container-id'), 'unknown');
  // A "no such object" answer about a DIFFERENT id proves nothing about this one.
  const other = hex(randomBytes(32));
  const real = d.run.bind(d);
  d.run = async () => ({ status: 1, stdout: '', stderr: `error: no such object: ${other}\n`, timedOut: false, failed: false });
  assert.equal(await p.state(id), 'unknown');
  d.run = real;
  for (const mode of ['daemon-down', 'permission', 'timeout', 'garbled', 'empty', 'wrong-id', 'inspect-error'] as Mode[]) {
    d.mode = mode; d.containers.delete(id);
    assert.equal(await p.state(id), 'unknown', `${mode} must be unknown, never absent or stopped`);
  }
});

test('terminate is kill-and-CONFIRM: a kill that does not stop the container is not accepted', async () => {
  const d = new FakeDocker(); const id = d.add('issuer');
  const a = new DockerAdapters(new DockerProject(d, 'c.yaml'), new Map(), fast);
  const target: Target = { role: 'issuer', incarnation: 'a'.repeat(32), instance_id: id };
  assert.deepEqual(await a.terminate(target, signal()),
    { role: 'issuer', incarnation: target.incarnation, instance_id: id, exited: true, descendants_exited: true });
  const hung = d.add('origin'); d.stubborn.add(hung);
  await assert.rejects(a.terminate({ ...target, role: 'origin', instance_id: hung }, signal()), /exit-unconfirmed/);
});

test('UNKNOWN Docker state is never exit evidence: every failure mode makes terminate fail', async () => {
  for (const mode of ['daemon-down', 'permission', 'timeout', 'garbled', 'empty', 'wrong-id', 'inspect-error'] as Mode[]) {
    const d = new FakeDocker(); const id = d.add('issuer'); d.mode = mode;
    const a = new DockerAdapters(new DockerProject(d, 'c.yaml'), new Map(), fast);
    await assert.rejects(a.terminate({ role: 'issuer', incarnation: 'a'.repeat(32), instance_id: id }, signal()), /exit-unconfirmed/, mode);
    assert.equal(d.containers.get(id)!.running, false, 'the kill itself was dispatched, but dispatch is not evidence');
  }
});

test('Redis discard accepts only the daemon saying the exact ID is gone; stopped-but-present and unknown are not discarded', async () => {
  const d = new FakeDocker(); const id = d.add('redis');
  const a = new DockerAdapters(new DockerProject(d, 'c.yaml'), new Map(), fast);
  assert.deepEqual(await a.discardRedis(id, signal()), { instance_id: id, exited: true });
  assert.ok(!d.containers.has(id));
  const stuck = d.add('redis'); d.sticky.add(stuck);
  await assert.rejects(a.discardRedis(stuck, signal()), /discard-unconfirmed/);
  for (const mode of ['daemon-down', 'permission', 'timeout', 'garbled', 'wrong-id'] as Mode[]) {
    const e = new FakeDocker(); const rid = e.add('redis'); e.mode = mode;
    const b = new DockerAdapters(new DockerProject(e, 'c.yaml'), new Map(), fast);
    await assert.rejects(b.discardRedis(rid, signal()), /discard-unconfirmed/, `${mode}: a removed container that cannot be inspected is NOT confirmed discarded`);
  }
});

test('an aborted signal stops terminate and discard without returning evidence', async () => {
  const d = new FakeDocker(); const id = d.add('issuer');
  const a = new DockerAdapters(new DockerProject(d, 'c.yaml'), new Map(), { ...fast, confirmMs: 5000 });
  const ctl = new AbortController(); ctl.abort();
  await assert.rejects(a.terminate({ role: 'issuer', incarnation: 'a'.repeat(32), instance_id: id }, ctl.signal), /exit-unconfirmed/);
  await assert.rejects(a.discardRedis(d.add('redis'), ctl.signal), /discard-unconfirmed/);
});

// A role double whose FENCE behavior tests control.
function double(role: RoleName, mode: 'good' | 'wrong-incarnation' | 'hang' | 'refuse') {
  const incarnation = hex(randomBytes(16));
  const handle = async (raw: unknown): Promise<Json> => {
    const req = raw as Json;
    if (mode === 'hang') await new Promise(() => undefined);
    const reply = { version: 1, request_id: req['request_id'], state: 'FENCED', run_id: null, config_digest: null,
      incarnation: mode === 'wrong-incarnation' ? hex(randomBytes(16)) : incarnation, ok: mode !== 'refuse', result: mode === 'refuse' ? 'ILLEGAL_STATE' : 'FENCED', data: {} };
    validateControlResponse(reply);
    return reply;
  };
  return { incarnation, link: new InProcessLink(role, handle, 60) as RoleLink };
}
function fixture(modes: Partial<Record<RoleName, 'good' | 'wrong-incarnation' | 'hang' | 'refuse'>>, roles: RoleName[] = ['issuer', 'client-A']) {
  const d = new FakeDocker(); const redis = d.add('redis');
  const links = new Map<RoleName, RoleLink>(); const participants: Target[] = [];
  for (const role of roles) {
    const id = d.add(SERVICE_FOR_ROLE[role]); const dbl = double(role, modes[role] ?? 'good');
    links.set(role, dbl.link); participants.push({ role, incarnation: dbl.incarnation, instance_id: id });
  }
  const adapters = new DockerAdapters(new DockerProject(d, 'c.yaml'), links, { ...fast, controlTimeoutMs: 60 });
  const barrier = new PartialResetBarrier({ run_id: 'a'.repeat(32), config_digest: 'b'.repeat(64), redis_instance_id: redis, participants }, adapters, 120);
  return { d, redis, participants, barrier, adapters };
}

test('partial barrier: strong acknowledgements end with a single-use receipt that unlocks exactly one Redis discard', async () => {
  const f = fixture({});
  const receipt = await f.barrier.fenceAll();
  assert.ok(f.participants.every((p) => f.d.containers.get(p.instance_id)!.running), 'clean fences do not kill anything');
  assert.equal(f.d.removals, 0, 'Redis is untouched until the receipt is used');
  await f.barrier.discardOldRedis(receipt);
  assert.ok(!f.d.containers.has(f.redis));
  await assert.rejects(f.barrier.discardOldRedis(receipt), /receipt-invalid/);
  assert.equal(await f.barrier.fenceAll(), receipt, 'fenceAll is shared, not repeated');
});

test('a FENCED reply from the wrong incarnation, a refusal and a hang all fall back to kill-and-confirm', async () => {
  const f = fixture({ issuer: 'wrong-incarnation', 'client-A': 'hang' });
  await f.barrier.fenceAll();
  for (const p of f.participants) assert.equal(f.d.containers.get(p.instance_id)!.running, false, `${p.role} was terminated`);
  const g = fixture({ issuer: 'refuse' });
  await g.barrier.fenceAll();
  assert.equal(g.d.containers.get(g.participants[0]!.instance_id)!.running, false);
  assert.equal(g.d.containers.get(g.participants[1]!.instance_id)!.running, true, 'a role that acknowledged strongly is left alone');
});

test('if any participant cannot be confirmed gone the barrier blocks and Redis is never discarded', async () => {
  const f = fixture({ 'client-A': 'hang' });
  f.d.stubborn.add(f.participants[1]!.instance_id);
  await assert.rejects(f.barrier.fenceAll(), /barrier-unconfirmed/);
  await assert.rejects(f.barrier.discardOldRedis({}), /receipt-invalid/);
  await assert.rejects(f.barrier.discardOldRedis(Object.freeze({})), /receipt-invalid/);
  assert.ok(f.d.containers.has(f.redis), 'old Redis still exists');
  assert.equal(f.d.removals, 0);
});

test('daemon loss, permission failure, timeout or garbled inspection during the barrier: ZERO Redis-discard calls', async () => {
  for (const mode of ['daemon-down', 'permission', 'timeout', 'garbled', 'wrong-id', 'empty'] as Mode[]) {
    const f = fixture({ issuer: 'hang', 'client-A': 'hang' }); // hung roles force termination, which needs real confirmation
    f.d.mode = mode;
    await assert.rejects(f.barrier.fenceAll(), /barrier-unconfirmed/, mode);
    await assert.rejects(f.barrier.discardOldRedis(Object.freeze({})), /receipt-invalid/, mode);
    assert.equal(f.d.removals, 0, `${mode}: Redis must not be removed while any exit is unconfirmed`);
    assert.ok(f.d.containers.has(f.redis));
  }
  // Even when only ONE participant's state is unknown, nothing is discarded.
  const g = fixture({ issuer: 'hang', 'client-A': 'hang' });
  g.d.mode = 'daemon-down'; g.d.modeFor = new Set([g.participants[0]!.instance_id]);
  await assert.rejects(g.barrier.fenceAll(), /barrier-unconfirmed/);
  assert.equal(g.d.removals, 0);
});

test('an unconfirmed Redis discard is terminal: no second attempt', async () => {
  const f = fixture({});
  f.d.sticky.add(f.redis);
  const receipt = await f.barrier.fenceAll();
  await assert.rejects(f.barrier.discardOldRedis(receipt), /discard-unconfirmed/);
  await assert.rejects(f.barrier.discardOldRedis(receipt), /receipt-invalid/);
});

const SPKI = 'MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAyxrta2qV9bHOATpM_KsluUsuZKIwNOQlCn6rQ8DfOowSmTrxKxEZCNS0cb7DHUtsmtnN2pBhKi7pA1I-beWiJNawLwnlw3TQz-Adj1KcUAp4ovZ5CPpoK1orQwyB6vGvcte155T8mKMTknaHl1fORTtSbvm_bOuZl5uEI7kPRGGiKvN6qwz1cz91l6vkTTHHMttooYHGy75gfYwOUuBlX9mZbcWE7KC-h6-814ozfRex26noKLvYHikTFxROf_ifVWGXCbCWy7nqR0zq0mTCBz_kl0DAHwDhCRBgZpg9IeX4PwhuLoI8h5zUPO9wDSo1Kpur1hLQPK0C2xNLfiJaXwIDAQAB';
async function servedOrigin() {
  const manifest = makeManifest({ run_id: hex(randomBytes(16)), run_start_ms: Date.now(), token_key_spki_b64url: SPKI, snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40) });
  const digest = configurationDigest(manifest);
  const origin = new OriginRole({ listen: { host: '127.0.0.1', port: 0 }, drainMs: 200 });
  const first = await origin.handle({ version: 1, request_id: hex(randomBytes(16)), command: 'STATUS', run_id: null, config_digest: null, target_incarnation: null, payload: {} });
  const incarnation = first['incarnation'] as string;
  const send = (command: string, over: Json = {}, payload: Json = {}) => origin.handle({ version: 1, request_id: hex(randomBytes(16)), command, run_id: manifest.run_id, config_digest: digest, target_incarnation: incarnation, payload, ...over });
  await send('PREPARE_RUN', { config_digest: null }, { manifest, proposed_config_digest: digest, role: 'origin', role_config: {} });
  await send('CHECK_READY'); await send('ENABLE');
  const get = (headers: Record<string, string>) => new Promise<void>((resolve, reject) => {
    const r = httpRequest({ host: '127.0.0.1', port: origin.address!.port, path: '/resource', headers, agent: false }, (res) => { res.resume(); res.on('end', () => resolve()); });
    r.on('error', reject); r.end();
  });
  await get({ 'X-TokenForge-Run': manifest.run_id }); await get({ 'X-TokenForge-Run': 'f'.repeat(32) });
  return { manifest, digest, origin, incarnation };
}

test('origin counters are read from the settled REPORT after its strong FENCE (received 2, mismatch 1, served 1)', async () => {
  const o = await servedOrigin();
  const d = new FakeDocker(); const redis = d.add('redis'); const originId = d.add('protected-origin');
  const links = new Map<RoleName, RoleLink>([['origin', new InProcessLink('origin', (r) => o.origin.handle(r), 500)]]);
  const adapters = new DockerAdapters(new DockerProject(d, 'c.yaml'), links, { ...fast, controlTimeoutMs: 500 });
  const barrier = new PartialResetBarrier({ run_id: o.manifest.run_id, config_digest: o.digest, redis_instance_id: redis,
    participants: [{ role: 'origin', incarnation: o.incarnation, instance_id: originId }] }, adapters, 500);
  assert.equal(adapters.originCounts, null, 'nothing is known before the barrier runs');
  await barrier.fenceAll();
  assert.deepEqual(adapters.originCounts, { protected_requests_received: 2, generation_mismatches: 1, resources_served: 1 });
});

test('if the REPORT cannot be bound to the old run, origin counts stay unavailable (null), never zero', async () => {
  const o = await servedOrigin();
  const d = new FakeDocker(); const redis = d.add('redis'); const originId = d.add('protected-origin');
  const links = new Map<RoleName, RoleLink>([['origin', new InProcessLink('origin', (r) => o.origin.handle(r), 500)]]);
  const adapters = new DockerAdapters(new DockerProject(d, 'c.yaml'), links, { ...fast, controlTimeoutMs: 500 });
  const barrier = new PartialResetBarrier({ run_id: 'a'.repeat(32), config_digest: 'b'.repeat(64), redis_instance_id: redis,
    participants: [{ role: 'origin', incarnation: o.incarnation, instance_id: originId }] }, adapters, 500);
  await barrier.fenceAll();
  assert.equal(adapters.originCounts, null);
});

test('a full eight-role deployment must use the real ResetBarrier, not this one', () => {
  const d = new FakeDocker(); const redis = d.add('redis');
  const roles: RoleName[] = ['gateway', 'issuer', 'origin', 'client-A', 'client-B', 'client-C', 'client-D', 'client-E'];
  const participants = roles.map((role) => ({ role, incarnation: hex(randomBytes(16)), instance_id: d.add(SERVICE_FOR_ROLE[role]) }));
  const adapters = new DockerAdapters(new DockerProject(d, 'c.yaml'), new Map());
  assert.throws(() => new PartialResetBarrier({ run_id: 'a'.repeat(32), config_digest: 'b'.repeat(64), redis_instance_id: redis, participants }, adapters), /use-ResetBarrier/);
});

const NL = String.fromCharCode(10);
test('exit monitor reads the container ID from both Docker event layouts and ignores other containers; stream loss is reported as loss of every role', () => {
  const child = Object.assign(new EventEmitter(), { stdout: new PassThrough(), stderr: new PassThrough(), kill() { /* test double */ } });
  const d = new FakeDocker(); d.spawn = () => child as unknown as ChildProcess;
  const a = d.add('issuer'), b = d.add('client-c');
  const project = new DockerProject(d, 'c.yaml');
  const lost: string[] = [];
  const stop = project.watch([{ role: 'issuer', container_id: a }, { role: 'client-C', container_id: b }], (r) => lost.push(r));
  child.stdout.write(JSON.stringify({ Type: 'container', Action: 'die', Actor: { ID: b, Attributes: {} } }) + NL);
  child.stdout.write(JSON.stringify({ status: 'die', id: a }) + NL);
  child.stdout.write(JSON.stringify({ Type: 'container', Action: 'die', Actor: { ID: hex(randomBytes(32)) } }) + NL + 'not json' + NL);
  assert.deepEqual(lost, ['client-C', 'issuer']);
  lost.length = 0;
  child.emit('close'); // the event stream itself died: unsafe, every watched role counts as lost
  assert.deepEqual(lost.sort(), ['client-C', 'issuer']);
  stop();
});
