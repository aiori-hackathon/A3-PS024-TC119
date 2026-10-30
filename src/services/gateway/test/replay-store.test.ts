import test from 'node:test';
import assert from 'node:assert/strict';
import golden from '../../../contracts/fixtures/policy-golden.json' with { type: 'json' };
import { configurationDigest, makeManifest, type Manifest } from '../../../contracts/lib/index.ts';
import { REPLAY_SCRIPTS } from '../src/replay-scripts.ts';
import { ReplayStore, type ReplayConnection, type ReplayFault } from '../src/replay-store.ts';

function manifest(profile: 'B0' | 'B1' = 'B1') {
  return makeManifest({ run_id: golden.manifest.run_id, run_start_ms: golden.manifest.run_start_ms,
    token_key_spki_b64url: golden.manifest.token_key_spki_b64url, gateway_profile: profile,
    snapshot_script_sha1: REPLAY_SCRIPTS.snapshot.sha1, claim_script_sha1: REPLAY_SCRIPTS.claim.sha1 });
}
const candidate = () => ({ kind: 'claim-candidate', epoch: 0, spend_id: 'a'.repeat(64) });
function snapshot(m: Manifest) {
  return ['SNAPSHOT', m.run_id, m.token_key_id, configurationDigest(m), m.run_start_ms + 300000,
    0, m.run_start_ms, m.run_start_ms + m.epoch_ms];
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(r => { resolve = r; });
  return { promise, resolve };
}
class Channel implements ReplayConnection {
  connectCount = 0;
  closeCount = 0;
  loss = () => {};
  calls: { command: string; args: (string | number)[] }[] = [];
  intercept?: (command: string, args: (string | number)[]) => unknown;
  throwOnClose = false;
  m: Manifest;
  constructor(m: Manifest) { this.m = m; }
  async connect() { this.connectCount++; }
  close() { this.closeCount++; if (this.throwOnClose) throw Error('private cleanup detail'); }
  onLoss(fn: () => void) { this.loss = fn; }
  async call(command: string, ...args: (string | number)[]): Promise<unknown> {
    this.calls.push({ command, args });
    if (this.intercept) return this.intercept(command, args);
    return this.normal(command, args);
  }
  normal(command: string, args: (string | number)[]): unknown {
    const m = this.m;
    switch (command) {
      case 'TYPE': return 'hash';
      case 'PTTL': return -1;
      case 'HLEN': return args[0] === 'pp:clock' ? 4 : 8;
      case 'HMGET': {
        const fields: Record<string, string> = args[0] === 'pp:clock'
          ? { run_id: m.run_id, last_now_ms: String(m.run_start_ms), highest_epoch: '0', closed: '0' }
          : { schema_version: '1', run_id: m.run_id, token_type: '2', token_key_id: m.token_key_id,
            config_digest: configurationDigest(m), run_start_ms: String(m.run_start_ms), epoch_ms: '600000', guard_ms: '30000' };
        return args.slice(1).map(f => fields[String(f)]);
      }
      case 'SCRIPT': return [1, 1];
      case 'EVALSHA': return args[0] === REPLAY_SCRIPTS.snapshot.sha1 ? snapshot(m) : ['CLAIMED', m.run_start_ms + m.epoch_ms + m.guard_ms];
      default: throw Error('Unexpected adapter command');
    }
  }
}
async function ready(profile: 'B0' | 'B1' = 'B1') {
  const m = manifest(profile);
  const channels = Array.from({ length: m.limits.gateway.redis_connections_per_worker }, () => new Channel(m));
  const faults: ReplayFault[] = [];
  const store = await ReplayStore.prepare(m, channels, reason => { faults.push(reason); });
  return { m, channels, faults, store };
}

test('readiness rejects unreviewed script hashes and wrong/aliased pool size before connecting', async () => {
  for (const change of ['snapshot_script_sha1', 'claim_script_sha1'] as const) {
    const m = manifest(); m[change] = 'f'.repeat(40);
    const channels = [new Channel(m), new Channel(m)];
    await assert.rejects(() => ReplayStore.prepare(m, channels, () => {}), /replay-configuration-invalid/);
    assert.ok(channels.every(c => c.connectCount === 0 && c.closeCount === 1));
  }
  const m = manifest(), c = new Channel(m);
  await assert.rejects(() => ReplayStore.prepare(m, [c, c], () => {}), /replay-configuration-invalid/);
  await assert.rejects(() => ReplayStore.prepare(m, [c], () => {}), /replay-configuration-invalid/);
});

test('readiness compares every policy field, including unchanged digest beside altered run_start', async () => {
  const m = manifest('B0');
  for (let index = 0; index < 8; index++) {
    const c = new Channel(m);
    c.intercept = (cmd, args) => {
      const value = c.normal(cmd, args);
      if (cmd === 'HMGET' && args[0] === 'pp:policy') (value as unknown[])[index] = 'wrong';
      return value;
    };
    await assert.rejects(() => ReplayStore.prepare(m, [c], () => {}), /replay-preparation-failed/);
    assert.equal(c.closeCount, 1);
    assert.ok(!c.calls.some(x => x.command === 'EVALSHA'));
  }
});

test('stalled connect is bounded and a late connection cannot finish readiness after terminal failure', async () => {
  const m = manifest(), channels = [new Channel(m), new Channel(m)];
  const pending = deferred<void>(); channels[0]!.connect = () => pending.promise;
  const faults: ReplayFault[] = [];
  await assert.rejects(() => ReplayStore.prepare(m, channels, reason => { faults.push(reason); }), /replay-preparation-failed/);
  assert.deepEqual(faults, ['dependency-lost']);
  assert.ok(channels.every(c => c.closeCount === 1));
  pending.resolve(); await Promise.resolve();
  assert.equal(channels[0]!.calls.length, 0);
});

test('readiness rejects wrong cardinality, expiring guards, non-initial clock and missing scripts', async () => {
  const m = manifest('B0');
  for (const fault of ['TYPE', 'PTTL', 'HLEN', 'HMGET', 'SCRIPT']) {
    const c = new Channel(m);
    c.intercept = (cmd, args) => {
      if (cmd === fault && (fault !== 'HMGET' || args[0] === 'pp:clock')) {
        return ({ TYPE: 'string', PTTL: 1000, HLEN: 20, HMGET: [m.run_id, String(m.run_start_ms + 1), '0', '0'], SCRIPT: [1, 0] } as Record<string, unknown>)[fault];
      }
      return c.normal(cmd, args);
    };
    await assert.rejects(() => ReplayStore.prepare(m, [c], () => {}), /replay-preparation-failed/);
    assert.equal(c.closeCount, 1);
  }
});

test('malformed or unsafe snapshots permanently close the pool without exposing raw errors', async () => {
  for (const reply of [null, true, ['SNAPSHOT'], ['RUN_UNAVAILABLE'], ['CLOCK_UNSAFE'], ['SNAPSHOT', 'secret-error']]) {
    const { store, channels, faults } = await ready();
    channels[0]!.intercept = () => reply;
    assert.deepEqual(await store.snapshot(), { kind: 'unavailable' });
    assert.equal(store.status.state, 'closed');
    assert.equal(faults.length, 1);
    assert.ok(channels.every(c => c.closeCount === 1));
    const count = channels.reduce((n, c) => n + c.calls.length, 0);
    assert.deepEqual(await store.snapshot(), { kind: 'unavailable' });
    assert.deepEqual(await store.claim(candidate()), { kind: 'unavailable' });
    assert.equal(channels.reduce((n, c) => n + c.calls.length, 0), count);
  }
});

test('strict claim replies reject truthy arrays and incorrect expiry; ordinary replay/epoch keep the pool open', async () => {
  for (const raw of [[], [true], ['CLAIMED'], ['CLAIMED', 1], ['CLAIMED', '1'], ['CLAIMED', 1, 'extra'], ['NOPE'], ['CLOCK_UNSAFE']]) {
    const { store, channels } = await ready('B0'); channels[0]!.intercept = () => raw;
    assert.deepEqual(await store.claim(candidate()), { kind: 'unavailable' });
    assert.equal(store.status.state, 'closed');
  }
  const { store, channels } = await ready('B0');
  for (const [tag, reason] of [['ALREADY_SPENT', 'token-already-redeemed'], ['EPOCH_CLOSED', 'token-expired']]) {
    channels[0]!.intercept = () => [tag];
    assert.deepEqual(await store.claim(candidate()), { kind: 'rejected', reason });
    assert.equal(store.status.state, 'ready');
  }
  store.close();
});

test('one RPC per connection, bounded capacity, and loss on one connection suppresses another late success', async () => {
  const { m, store, channels, faults } = await ready();
  const pending = [deferred<unknown>(), deferred<unknown>()];
  channels.forEach((c, i) => { c.intercept = () => pending[i]!.promise; });
  const a = store.snapshot(), b = store.claim(candidate());
  assert.deepEqual(await store.snapshot(), { kind: 'busy' });
  assert.equal(store.status.state, 'ready');
  channels[0]!.loss(); channels[1]!.loss();
  pending[0]!.resolve(snapshot(m)); pending[1]!.resolve(['CLAIMED', m.run_start_ms + 630000]);
  assert.deepEqual(await a, { kind: 'unavailable' });
  assert.deepEqual(await b, { kind: 'unavailable' });
  assert.deepEqual(faults, ['dependency-lost']);
  assert.ok(channels.every(c => c.closeCount === 1));
});

test('monotonic post-await deadline rejects late success even before a delayed timer can execute', async () => {
  const { m, store, channels, faults } = await ready('B0');
  channels[0]!.intercept = async () => {
    const until = performance.now() + m.limits.gateway.redis_command_timeout_ms + 20;
    while (performance.now() < until) { /* deliberately block ONLY this test's event loop */ }
    return snapshot(m);
  };
  assert.deepEqual(await store.snapshot(), { kind: 'unavailable' });
  assert.deepEqual(faults, ['dependency-lost']);
});

test('command timeout closes all connections and a late result cannot reopen or resend', async () => {
  const { m, store, channels, faults } = await ready('B0');
  const pending = deferred<unknown>(); channels[0]!.intercept = () => pending.promise;
  assert.deepEqual(await store.claim(candidate()), { kind: 'unavailable' });
  const count = channels[0]!.calls.length;
  pending.resolve(['CLAIMED', m.run_start_ms + 630000]);
  await Promise.resolve();
  assert.deepEqual(await store.claim(candidate()), { kind: 'unavailable' });
  assert.equal(channels[0]!.calls.length, count);
  assert.deepEqual(faults, ['dependency-lost']);
});

test('explicit close is terminal and candidate primitive copies survive caller mutation', async () => {
  const { m, store, channels } = await ready('B0');
  const pending = deferred<unknown>(); channels[0]!.intercept = () => pending.promise;
  const c = candidate(); const result = store.claim(c);
  c.epoch = 1; c.spend_id = 'b'.repeat(64);
  const sent = channels[0]!.calls.at(-1)!;
  assert.equal(sent.command, 'EVALSHA');
  assert.deepEqual(sent.args.slice(-2), ['0', 'a'.repeat(64)]);
  store.close(); pending.resolve(['CLAIMED', m.run_start_ms + 630000]);
  assert.deepEqual(await result, { kind: 'unavailable' });
  assert.equal(store.status.fault, null);
});

test('cleanup and observer exceptions cannot leave the other connection usable or leak diagnostics', async () => {
  const m = manifest(), channels = [new Channel(m), new Channel(m)];
  let notifications = 0;
  const store = await ReplayStore.prepare(m, channels, () => { notifications++; throw Error('private observer detail'); });
  channels[0]!.throwOnClose = true;
  channels[0]!.intercept = () => { throw Error('private Redis command detail'); };
  assert.deepEqual(await store.snapshot(), { kind: 'unavailable' });
  assert.equal(store.status.fault, 'dependency-lost');
  assert.equal(notifications, 1);
  assert.ok(channels.every(c => c.closeCount === 1));
});

test('invalid internal candidates never invoke Redis and terminally close the pool', async () => {
  for (const c of [null, {}, { ...candidate(), epoch: -0 }, { ...candidate(), epoch: Number.MAX_SAFE_INTEGER }, { ...candidate(), spend_id: 'A'.repeat(64) }]) {
    const { store, channels } = await ready('B0'); const count = channels[0]!.calls.length;
    assert.deepEqual(await store.claim(c), { kind: 'unavailable' });
    assert.equal(channels[0]!.calls.length, count);
    assert.equal(store.status.state, 'closed');
  }
});
