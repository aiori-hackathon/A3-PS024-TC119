// Logic of the controller-orchestrated scenarios against a small model of gateway behavior. The model proves each handler
// reaches the right verdict for a correct gateway AND for broken ones (double accept, no fail-closed, revived by reload,
// refunded claim). The real gateway, Redis and Docker faults are exercised by the deployed suite, not here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { makeManifest, hex } from '../../../contracts/lib/index.ts';
import { ORCHESTRATED, captureOldCredentials, redisFault, restartAndReset, stolenUnusedToken, upstreamFailure, type OrchestrationContext } from '../src/controller/orchestrated.ts';
import { Vault, type FaultPort, type HarnessPort, type Json, type RedisFault } from '../src/controller/ports.ts';

const SPKI = 'MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAyxrta2qV9bHOATpM_KsluUsuZKIwNOQlCn6rQ8DfOowSmTrxKxEZCNS0cb7DHUtsmtnN2pBhKi7pA1I-beWiJNawLwnlw3TQz-Adj1KcUAp4ovZ5CPpoK1orQwyB6vGvcte155T8mKMTknaHl1fORTtSbvm_bOuZl5uEI7kPRGGiKvN6qwz1cz91l6vkTTHHMttooYHGy75gfYwOUuBlX9mZbcWE7KC-h6-814ozfRex26noKLvYHikTFxROf_ifVWGXCbCWy7nqR0zq0mTCBz_kl0DAHwDhCRBgZpg9IeX4PwhuLoI8h5zUPO9wDSo1Kpur1hLQPK0C2xNLfiJaXwIDAQAB';
const manifest = makeManifest({ run_id: hex(randomBytes(16)), run_start_ms: Date.now(), token_key_spki_b64url: SPKI, snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40) });

/** A model gateway. Flags bend it into the broken behaviors the handlers must catch. */
class World {
  spent = new Set<string>(); keyId = manifest.token_key_id; closed = false; originPaused = false;
  doubleAccept = false; ignoreFaults = false; reviveOnReload = false; refund = false; nonMatchingKey = false;
  presentations: { client: string; status: number }[] = [];
  respond(token: Uint8Array): { status: number; label: string | null } {
    const id = Buffer.from(token).toString('hex'), key = Buffer.from(token.subarray(66, 98)).toString('hex');
    if (this.closed && !this.ignoreFaults) return { status: 503, label: 'authorization-unavailable' };
    if (key !== this.keyId) return { status: 401, label: 'token-key-unknown' };
    if (this.spent.has(id) && !this.doubleAccept) return { status: 401, label: 'token-already-redeemed' };
    this.spent.add(id);
    if (this.originPaused) { if (this.refund) this.spent.delete(id); return { status: 504, label: null }; }
    return { status: 200, label: null };
  }
}
class FakeHarness implements HarnessPort {
  world: World; issued = 0; keyOverride: string | null = null;
  constructor(world: World) { this.world = world; }
  async issue(_c: string, _m: unknown, vouchers: string[]) {
    return vouchers.map(() => { const t = randomBytes(354); t[0] = 0; t[1] = 2; Buffer.from(this.keyOverride ?? this.world.keyId, 'hex').copy(t, 66); this.issued++; return Uint8Array.from(t); });
  }
  async present(client: string, _m: unknown, tokens: Uint8Array[]) { return tokens.map((t) => { const r = this.world.respond(t); this.world.presentations.push({ client, status: r.status }); return r; }); }
}
class FakeFaults implements FaultPort {
  world: World; calls: string[] = [];
  constructor(world: World) { this.world = world; }
  async redis(kind: RedisFault) { this.calls.push(kind); this.world.closed = true; }
  async reloadScripts() { this.calls.push('reload'); if (this.world.reviveOnReload) this.world.closed = false; }
  async pauseOrigin() { this.calls.push('pause'); this.world.originPaused = true; }
  async unpauseOrigin() { this.calls.push('unpause'); this.world.originPaused = false; }
}
function ctx(world = new World(), over: Partial<OrchestrationContext> = {}) {
  const harness = new FakeHarness(world), faults = new FakeFaults(world), vault = new Vault();
  let vouchers = 8;
  const gateway: Json = { ok: true, state: 'ENABLED', data: { ready: true, run_closed: false, fault: null } };
  const c: OrchestrationContext = {
    manifest, harness, faults, vault, takeVouchers: (n) => (vouchers >= n ? (vouchers -= n, Array.from({ length: n }, () => 'v')) : null),
    gatewayStatus: async () => (world.closed ? { ok: true, state: 'FENCED', data: { ready: false, run_closed: true, fault: 'unsafe-state' } } : gateway), sleep: async () => undefined, ...over,
  };
  return { world, harness, faults, vault, c };
}

test('S16 stolen-unused-token: the thief wins, the holder loses, and that is reported as the bearer limit', async () => {
  const { c, world } = ctx();
  const r = await stolenUnusedToken(c);
  assert.equal(r.status, 'PASS'); assert.equal(r.expected, 'bearer-limit');
  assert.deepEqual(world.presentations.map((p) => [p.client, p.status]), [['B', 200], ['A', 401]], 'thief first from another client, holder second');
  assert.equal(r.counters['claims_successful'], 1); assert.equal(r.counters['replays_rejected'], 1);
  // A gateway that let both succeed would be a double spend, not a bearer limit.
  const broken = ctx(); broken.world.doubleAccept = true;
  assert.equal((await stolenUnusedToken(broken.c)).status, 'FAIL');
  assert.equal((await stolenUnusedToken(ctx(new World(), { harness: undefined }).c)).status, 'INCONCLUSIVE');
  assert.equal((await stolenUnusedToken(ctx(new World(), { takeVouchers: () => null }).c)).status, 'INCONCLUSIVE');
});

test('S13 restart-and-reset: old spent and unused credentials fail under the new key; the fresh credential works once', async () => {
  const old = ctx(); // OLD generation
  assert.equal(await captureOldCredentials(old.c), true);
  assert.equal(old.world.presentations.length, 1, 'one credential is spent in the old run');
  // NEW generation: different key, same quarantined vault.
  const next = ctx(new World(), { vault: old.vault });
  next.world.keyId = hex(randomBytes(32));
  next.harness.keyOverride = next.world.keyId; // fresh credentials carry the new key
  const manifestNew = { ...manifest, token_key_id: next.world.keyId };
  const r = await restartAndReset({ ...next.c, manifest: manifestNew });
  assert.equal(r.status, 'PASS', JSON.stringify(r));
  assert.equal(r.expected, 'recovered');
  assert.equal(old.vault.take('old-run'), undefined, 'the quarantined credentials were consumed');
  // If the "new" generation had the SAME key, the old spent credential would still fail as a replay, but the proof of a fresh key is gone.
  const old2 = ctx(); await captureOldCredentials(old2.c);
  const sameKey = ctx(new World(), { vault: old2.vault });
  assert.equal((await restartAndReset(sameKey.c)).status, 'FAIL');
  assert.equal((await restartAndReset(ctx().c)).status, 'INCONCLUSIVE', 'without captured credentials it is not tested, never a pass');
});

test('S13 capture refuses to quarantine anything unless the spent credential really was accepted', async () => {
  const broken = ctx(); broken.world.closed = true; // gateway refuses everything
  assert.equal(await captureOldCredentials(broken.c), false);
  assert.equal(broken.vault.take('old-run'), undefined);
});

for (const kind of ['script-flush', 'clock-delete', 'policy-corrupt', 'redis-stop', 'clock-regress'] as RedisFault[]) {
  test(`S12/S17 fault "${kind}": valid unspent tokens are refused afterwards, reload cannot revive, the gateway reports itself closed`, async () => {
    const { c, faults } = ctx();
    const r = await redisFault(kind, 'fail-closed')(c);
    assert.equal(r.status, 'PASS', JSON.stringify(r));
    assert.equal(faults.calls[0], kind);
    assert.equal(faults.calls.includes('reload'), kind !== 'redis-stop', 'a live repair is attempted (except when Redis itself is gone)');
    assert.equal(r.counters['requests_rejected'], 3);
  });
}

test('S12 fails for a gateway that keeps serving, one that a reload revives, or one that does not report closure', async () => {
  for (const [name, bend] of [['keeps serving', (w: World) => { w.ignoreFaults = true; }], ['revived by reload', (w: World) => { w.reviveOnReload = true; }]] as [string, (w: World) => void][]) {
    const x = ctx(); bend(x.world);
    assert.equal((await redisFault('script-flush', 'fail-closed')(x.c)).status, 'FAIL', name);
  }
  const silent = ctx(new World(), { gatewayStatus: async () => ({ ok: true, state: 'ENABLED', data: { ready: true, run_closed: false, fault: null } }) });
  assert.equal((await redisFault('script-flush', 'fail-closed')(silent.c)).status, 'FAIL', 'closure must be reported by the gateway itself');
  assert.equal((await redisFault('script-flush', 'fail-closed')(ctx(new World(), { faults: undefined }).c)).status, 'INCONCLUSIVE');
});

test('S11 upstream-failure: a stalled origin gives 504, the claim stays spent, and the unpause happens even if presenting throws', async () => {
  const { c, faults, world } = ctx();
  const r = await upstreamFailure(c);
  assert.equal(r.status, 'PASS', JSON.stringify(r));
  assert.deepEqual(faults.calls, ['pause', 'unpause']);
  assert.deepEqual(world.presentations.map((p) => p.status), [504, 401], 'one forward attempt, then a replay: no retry, no refund');
  const refund = ctx(); refund.world.refund = true;
  assert.equal((await upstreamFailure(refund.c)).status, 'FAIL', 'a refunded claim would let the token be spent again');
  const exploding = ctx(); exploding.harness.present = async () => { throw new Error('boom'); };
  await assert.rejects(upstreamFailure(exploding.c));
  assert.equal(exploding.faults.calls.at(-1), 'unpause', 'the origin is never left paused');
});

test('every orchestrated key maps to a handler, fault families are fully enumerated, and secrets stay out of results', async () => {
  for (const key of ['stolen-unused-token', 'restart-and-reset', 'upstream-failure', 'redis-failure:script-flush', 'redis-failure:clock-delete', 'redis-failure:policy-corrupt', 'redis-failure:redis-stop', 'clock-rollback:clock-regress']) {
    assert.equal(typeof ORCHESTRATED[key], 'function', key);
  }
  const { c } = ctx();
  const r = await stolenUnusedToken(c);
  const text = JSON.stringify(r);
  assert.doesNotMatch(text, /[A-Za-z0-9_-]{43,}/, 'no token- or voucher-shaped string in a scenario result');
});
