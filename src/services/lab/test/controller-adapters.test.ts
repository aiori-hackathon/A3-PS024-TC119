// Unit coverage of the controller's real-world adapters: Redis over docker exec, gateway launch over docker exec, and the
// identity-bound cleanup scope. The Docker CLI is a fake; the live behavior is exercised by infra/scripts/check-controller.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { ChildProcess } from 'node:child_process';
import { hex, makeManifest, configurationDigest } from '../../../contracts/lib/index.ts';
import { REPLAY_SCRIPTS } from '../../../contracts/lib/replay.ts';
import { DockerRedis, DockerRedisIo, quoteForRedisCli } from '../src/controller/redis-docker.ts';
import { DockerGatewayLauncher, GATEWAY_LISTEN_HOST } from '../src/controller/gateway-docker.ts';
import { CleanupScope, ScopeBarrier, discardRedis, stopRoles } from '../src/controller/scope.ts';
import type { DockerCli, RunOptions, RunResult } from '../src/controller/docker.ts';
import type { RedisIo } from '../../../contracts/lib/replay.ts';

/** A faithful-enough model of redis-cli's argument splitter (sdssplitargs) to prove quoting round-trips. */
function splitargs(line: string): string[] {
  const out: string[] = []; let i = 0;
  while (i < line.length) {
    while (line[i] === ' ') i++;
    if (i >= line.length) break;
    if (line[i] !== '"') throw new Error('unquoted');
    i++; const bytes: number[] = [];
    for (;;) {
      const c = line[i++];
      if (c === undefined) throw new Error('unterminated');
      if (c === '"') break;
      if (c === '\\') {
        const n = line[i++];
        if (n === 'x') { bytes.push(parseInt(line.slice(i, i + 2), 16)); i += 2; }
        else bytes.push(({ n: 10, r: 13, t: 9, b: 8, a: 7 } as Record<string, number>)[n!] ?? n!.charCodeAt(0));
      } else bytes.push(c.charCodeAt(0));
    }
    out.push(Buffer.from(bytes).toString('utf8'));
  }
  return out;
}

test('redis-cli quoting round-trips every awkward argument, including Lua with newlines, quotes, backslashes and non-ASCII', () => {
  const lua = REPLAY_SCRIPTS.claim.source;
  const cases = ['plain', '', 'with space', 'quote"inside', 'back\\slash', 'line\nbreak\r\ttab', 'ünïcödé ✓', '>pass:word!', '\x00\x01\x7f', lua, 'x'.repeat(5000)];
  for (const c of cases) assert.deepEqual(splitargs(quoteForRedisCli(c)), [c], JSON.stringify(c).slice(0, 40));
  assert.deepEqual(splitargs(['EVALSHA', 'abc', 2, 'k1'].map(quoteForRedisCli).join(' ')), ['EVALSHA', 'abc', '2', 'k1']);
});

class FakeCli implements DockerCli {
  runs: { args: string[]; options: RunOptions | undefined }[] = [];
  respond: (args: string[], options: RunOptions | undefined) => Partial<RunResult> = () => ({ status: 0, stdout: '"OK"\n' });
  async run(args: string[], options?: RunOptions): Promise<RunResult> {
    this.runs.push({ args, options });
    return { status: 0, stdout: '', stderr: '', timedOut: false, failed: false, ...this.respond(args, options) };
  }
  spawned: { args: string[]; child: FakeChild }[] = [];
  makeChild: (args: string[]) => FakeChild = () => new FakeChild();
  spawn(args: string[]): ChildProcess { const child = this.makeChild(args); this.spawned.push({ args, child }); return child as unknown as ChildProcess; }
}
class FakeChild extends EventEmitter {
  stdin = new PassThrough(); stdout = new PassThrough(); stderr = new PassThrough(); input = ''; killed = false;
  constructor() { super(); this.stdin.setEncoding('utf8'); this.stdin.on('data', (d: string) => { this.input += d; this.onInput(d); }); }
  protected onInput(_d: string): void { /* overridden */ }
  kill() { if (this.killed) return; this.killed = true; this.emit('close', null); }
}

test('Redis commands go over STDIN; the controller password travels by environment NAME only; Lua and the gateway password never reach argv', async () => {
  const cli = new FakeCli();
  cli.respond = () => ({ status: 0, stdout: '"OK"\n' });
  const controllerPassword = 'controller-secret-' + hex(randomBytes(8));
  const gatewayPassword = 'gateway-secret-' + hex(randomBytes(8)) + 'x'.repeat(16);
  const io = new DockerRedisIo(cli, 'a'.repeat(64), controllerPassword);
  await io.call('ACL', 'SETUSER', 'gateway', 'reset', 'on', `>${gatewayPassword}`);
  await io.call('SCRIPT', 'LOAD', REPLAY_SCRIPTS.snapshot.source);
  assert.equal(cli.runs.length, 2);
  for (const { args, options } of cli.runs) {
    const argv = args.join(' ');
    assert.ok(!argv.includes(controllerPassword) && !argv.includes(gatewayPassword), 'no password in argv');
    assert.ok(!argv.includes('local MAX'), 'no Lua in argv');
    assert.ok(args.includes('REDISCLI_AUTH') && !args.some((a) => a.startsWith('REDISCLI_AUTH=')), 'docker forwards the variable by name');
    assert.equal(options!.env!['REDISCLI_AUTH'], controllerPassword);
    assert.deepEqual(args.slice(0, 3), ['exec', '-i', '-e']);
    assert.ok(args.includes('a'.repeat(64)), 'addressed by immutable container ID');
  }
  assert.ok(cli.runs[0]!.options!.input!.includes(`>${gatewayPassword}`), 'the gateway password is on stdin');
  assert.deepEqual(splitargs(cli.runs[1]!.options!.input!.trim()), ['SCRIPT', 'LOAD', REPLAY_SCRIPTS.snapshot.source]);
});

test('Redis call failures are uncertain: timeouts, non-zero exits, error text and garbage all throw, once, with no detail', async () => {
  for (const bad of [{ timedOut: true, failed: true, status: null }, { status: 1 }, { stdout: 'error: NOPERM no permission' }, { stdout: '(error) ERR boom' }, { stdout: '' }, { stdout: 'not json' }] as Partial<RunResult>[]) {
    const cli = new FakeCli(); cli.respond = () => bad;
    const io = new DockerRedisIo(cli, 'a'.repeat(64), 'pw');
    await assert.rejects(io.call('PING'), (e: Error) => e.message === 'redis-call-failed' && !String(e.stack).includes('pw'));
    assert.equal(cli.runs.length, 1, 'no retry');
  }
});

test('DockerRedis.prepare takes the start from Redis TIME and the reviewed script hashes; install refuses a digest that does not match', async () => {
  const replies: unknown[] = [REPLAY_SCRIPTS.snapshot.sha1, REPLAY_SCRIPTS.claim.sha1, undefined, ['1793000000', '500000']];
  const calls: string[][] = [];
  const io: RedisIo = { call: async (c, ...a) => { calls.push([c, ...a.map(String)]); if (c === 'SCRIPT') { const r = replies.shift(); return r ?? (await import('../../../contracts/lib/replay.ts')).REPLAY_INITIALIZER.sha1; } return replies.shift(); } };
  const store = await new DockerRedis(io).prepare('a'.repeat(32));
  assert.equal(store.run_start_ms, 1793000000500);
  assert.equal(store.snapshot_script_sha1, '20b8aa1866d30e41364acb05826a5617d27f1c72');
  assert.equal(store.claim_script_sha1, 'c4a37fc975fe7f68e73c1e0d47b4c1779a182784');
  assert.deepEqual(calls.map((c) => c[0]), ['SCRIPT', 'SCRIPT', 'SCRIPT', 'TIME']);
  const m = makeManifest({ run_id: 'a'.repeat(32), run_start_ms: 1793000000500, token_key_spki_b64url: 'MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAyxrta2qV9bHOATpM_KsluUsuZKIwNOQlCn6rQ8DfOowSmTrxKxEZCNS0cb7DHUtsmtnN2pBhKi7pA1I-beWiJNawLwnlw3TQz-Adj1KcUAp4ovZ5CPpoK1orQwyB6vGvcte155T8mKMTknaHl1fORTtSbvm_bOuZl5uEI7kPRGGiKvN6qwz1cz91l6vkTTHHMttooYHGy75gfYwOUuBlX9mZbcWE7KC-h6-814ozfRex26noKLvYHikTFxROf_ifVWGXCbCWy7nqR0zq0mTCBz_kl0DAHwDhCRBgZpg9IeX4PwhuLoI8h5zUPO9wDSo1Kpur1hLQPK0C2xNLfiJaXwIDAQAB',
    snapshot_script_sha1: store.snapshot_script_sha1, claim_script_sha1: store.claim_script_sha1 });
  const never: RedisIo = { call: async () => { throw new Error('must not be called'); } };
  await assert.rejects(new DockerRedis(never).install(m, '0'.repeat(64)), /digest-mismatch/);
  assert.ok(configurationDigest(m));
});

test('a host-clock or hash mismatch cannot slip through prepare', async () => {
  const wrongSha: RedisIo = { call: async () => '0'.repeat(40) };
  await assert.rejects(new DockerRedis(wrongSha).prepare('a'.repeat(32)), /script-mismatch/);
});

// ------------------------------- gateway launcher -------------------------------------------------------------------
class ControlHelperChild extends FakeChild {
  readonly role: string; readonly up: () => boolean;
  constructor(role: string, up: () => boolean) { super(); this.role = role; this.up = up; }
  protected override onInput(d: string): void {
    if (!this.up()) { setImmediate(() => this.emit('close', 1)); return; } // socket missing: the helper exits non-zero
    for (const line of d.split('\n').filter(Boolean)) {
      const req = JSON.parse(line);
      this.stdout.write(JSON.stringify({ version: 1, request_id: req.request_id, state: 'FENCED', run_id: null, config_digest: null, incarnation: 'c'.repeat(32), ok: true, result: 'STATUS', data: { ready: false, run_closed: false, fault: null } }) + '\n');
    }
  }
}
function secretsFixture() {
  const dir = mkdtempSync(join(tmpdir(), 'ps024-gw-'));
  mkdirSync(join(dir, 'gateway'));
  writeFileSync(join(dir, 'gateway', 'tls.key'), 'KEY-PEM-PLACEHOLDER'); writeFileSync(join(dir, 'gateway', 'tls.crt'), 'CERT-PEM-PLACEHOLDER');
  return dir;
}

test('gateway launch: serve.mjs is started inside the exact container; its stdin gets exactly {listen_host, tls, redis}; nothing secret is in argv', async () => {
  const cli = new FakeCli(); let socketUp = false;
  let serve: FakeChild | null = null;
  cli.makeChild = (args) => {
    if (args.includes('/app/dist/serve.mjs')) { serve = new FakeChild(); setTimeout(() => { socketUp = true; }, 40); return serve; }
    return new ControlHelperChild('gateway', () => socketUp);
  };
  const launcher = new DockerGatewayLauncher(cli, { role: 'gateway', container_id: 'f'.repeat(64) }, { secretsDir: secretsFixture(), retryMs: 10 });
  const password = 'gw-password-' + hex(randomBytes(12)) + 'z'.repeat(10);
  const link = await launcher.launch({ redis: { username: 'gateway', password } });
  assert.ok(link, 'a control link to the serving process is returned');
  const first = cli.spawned[0]!;
  assert.deepEqual(first.args, ['exec', '-i', 'f'.repeat(64), 'node', '/app/dist/serve.mjs']);
  const input = JSON.parse(serve!.input);
  assert.deepEqual(Object.keys(input).sort(), ['listen_host', 'redis', 'tls']);
  assert.deepEqual(input, { listen_host: GATEWAY_LISTEN_HOST, tls: { key: 'KEY-PEM-PLACEHOLDER', cert: 'CERT-PEM-PLACEHOLDER' }, redis: { username: 'gateway', password } });
  assert.notEqual(input.listen_host, '0.0.0.0');
  for (const s of cli.spawned) assert.ok(!s.args.join(' ').includes(password) && !s.args.some((a) => a.includes('PEM-PLACEHOLDER') || a === '-e'), 'no secret or environment in any argv');
  assert.ok(cli.spawned.filter((s) => s.args.includes('/app/dist/control-helper.mjs')).length >= 2, 'the control socket did not exist at first; the launcher retried');
  link.close();
  await assert.rejects(launcher.launch({ redis: { username: 'gateway', password } }), /already-launched/);
});

test('gateway launch fails closed if the serving process exits early or the control socket never appears', async () => {
  const dead = new FakeCli();
  dead.makeChild = (args) => { const c = args.includes('/app/dist/serve.mjs') ? new FakeChild() : new ControlHelperChild('gateway', () => false); if (args.includes('/app/dist/serve.mjs')) setImmediate(() => c.emit('close', 1)); return c; };
  await assert.rejects(new DockerGatewayLauncher(dead, { role: 'gateway', container_id: 'f'.repeat(64) }, { secretsDir: secretsFixture(), retryMs: 5, attempts: 20 }).launch({ redis: { username: 'gateway', password: 'p'.repeat(40) } }), /gateway-control-unavailable/);
  const missing = new FakeCli(); missing.makeChild = (args) => (args.includes('/app/dist/serve.mjs') ? new FakeChild() : new ControlHelperChild('gateway', () => false));
  const launcher = new DockerGatewayLauncher(missing, { role: 'gateway', container_id: 'f'.repeat(64) }, { secretsDir: secretsFixture(), retryMs: 5, attempts: 5 });
  await assert.rejects(launcher.launch({ redis: { username: 'gateway', password: 'p'.repeat(40) } }), /gateway-control-unavailable/);
  assert.ok(missing.spawned[0]!.child.killed, 'the serving client is terminated when the launch is abandoned');
});

// ------------------------------- cleanup scope ----------------------------------------------------------------------
function adapters(failFor: Set<string> = new Set(), failRedis = false) {
  const log: string[] = [];
  return { log, a: {
    async terminate(t: { instance_id: string }) { log.push('terminate:' + t.instance_id.slice(0, 4)); if (failFor.has(t.instance_id)) throw new Error('exit-unconfirmed'); return {}; },
    async discardRedis(id: string) { log.push('discard:' + id.slice(0, 4)); if (failRedis) throw new Error('discard-unconfirmed'); return {}; },
  } };
}
const ids = { a: '1'.repeat(64), b: '2'.repeat(64), c: '3'.repeat(64), redis: '4'.repeat(64) };
function scopeOf() { const s = new CleanupScope(); s.recordRole({ name: 'issuer', container_id: ids.a, role: 'issuer' }); s.recordRole({ name: 'origin', container_id: ids.b, role: 'origin' }); s.recordRole({ name: 'client-a', container_id: ids.c, role: 'client-A' }); s.recordRedis(ids.redis); return s; }

test('scope: every recorded role is terminated by immutable ID and confirmed before the old Redis is touched', async () => {
  const { log, a } = adapters(); const scope = scopeOf();
  assert.equal(await stopRoles(scope, a), true);
  assert.equal(log.filter((l) => l.startsWith('terminate')).length, 3); assert.ok(!log.some((l) => l.startsWith('discard')));
  assert.equal(await discardRedis(scope, a), true);
  assert.deepEqual(log.at(-1), 'discard:4444');
});

test('scope: one unconfirmed role makes the whole barrier fail, all others are still stopped, and Redis is never discarded', async () => {
  const { log, a } = adapters(new Set([ids.b])); const scope = scopeOf();
  const barrier = new ScopeBarrier(scope, a);
  await assert.rejects(barrier.fenceAll(), /scope-unconfirmed/);
  assert.equal(log.filter((l) => l.startsWith('terminate')).length, 3, 'a failing role does not stop the others being cleaned up');
  await assert.rejects(barrier.discardOldRedis({}), /receipt-invalid/);
  await assert.rejects(barrier.discardOldRedis(Object.freeze({})), /receipt-invalid/);
  assert.ok(!log.some((l) => l.startsWith('discard')));
});

test('scope barrier: single-use receipt; an unconfirmed discard is terminal', async () => {
  const { a } = adapters(); const barrier = new ScopeBarrier(scopeOf(), a);
  const receipt = await barrier.fenceAll();
  await barrier.discardOldRedis(receipt);
  await assert.rejects(barrier.discardOldRedis(receipt), /receipt-invalid/);
  const bad = adapters(new Set(), true); const b2 = new ScopeBarrier(scopeOf(), bad.a);
  await assert.rejects(b2.discardOldRedis(await b2.fenceAll()), /discard-unconfirmed/);
});

test('scope: an empty scope is trivially clean, and Redis-only scopes discard only with a confirmed answer', async () => {
  const { a } = adapters();
  assert.equal(await stopRoles(new CleanupScope(), a), true);
  assert.equal(await discardRedis(new CleanupScope(), a), true);
});
