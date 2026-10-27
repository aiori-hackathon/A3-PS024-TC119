import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import { publicVerif, TokenChallenge } from '@cloudflare/privacypass-ts';
import golden from '../../../contracts/fixtures/policy-golden.json' with { type: 'json' };
import known from '../../../contracts/fixtures/rfc9578-public.json' with { type: 'json' };
import {
  PROTOCOL, encodeBase64Url, fromHex, hex, makeManifest, redemptionContext,
  spendId, type Manifest,
} from '../../../contracts/lib/index.ts';
import { TokenVerifier } from '../src/token-verifier.ts';

const mode = publicVerif.BlindRSAMode.PSS;
let manifest: Manifest;
let verifier: TokenVerifier;
let issuer: InstanceType<typeof publicVerif.Issuer>;
let spki: Uint8Array;
let epochZero: Uint8Array;
let epochOne: Uint8Array;

async function issue(challenge: TokenChallenge): Promise<Uint8Array> {
  const client = new publicVerif.Client(mode);
  const request = await client.createTokenRequest(challenge, spki);
  return (await client.finalize(await issuer.issue(request))).serialize();
}
const challenge = (m: Manifest, epoch: number) =>
  new TokenChallenge(PROTOCOL.token_type, m.issuer_name, redemptionContext(m, epoch), [m.origin_name]);

before(async () => {
  const keys = await publicVerif.Issuer.generateKey(mode, { modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) });
  spki = await publicVerif.getPublicKeyBytes(keys.publicKey);
  manifest = makeManifest({
    run_id: hex(crypto.getRandomValues(new Uint8Array(16))), run_start_ms: 1700000000000,
    token_key_spki_b64url: encodeBase64Url(spki), snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40),
  });
  issuer = new publicVerif.Issuer(mode, manifest.issuer_name, keys.privateKey, keys.publicKey);
  verifier = await TokenVerifier.prepare(manifest);
  epochZero = await issue(challenge(manifest, 0));
  epochOne = await issue(challenge(manifest, 1));
});

test('valid signature and configured context yield only an atomic-claim candidate', async () => {
  assert.deepEqual(await verifier.verify(epochZero, 0), {
    kind: 'claim-candidate', spend_id: spendId(epochZero.subarray(0, PROTOCOL.auth_input_bytes)), epoch: 0,
  });
  assert.equal((await verifier.verify(epochOne, 1)).kind, 'claim-candidate');
});

test('repeated verification has no replay side effect and cannot substitute for a claim', async () => {
  const results = await Promise.all(Array.from({ length: 8 }, () => verifier.verify(epochZero, 0)));
  assert.ok(results.every(result => result.kind === 'claim-candidate'));
  assert.ok(results.every(result => !Object.hasOwn(result, 'authorized')));
});

test('signature receipts are opaque, single-use and bound to the verifier, with owned wire bytes', async () => {
  const input = epochZero.slice(); const pending = verifier.verifySignature(input); input.fill(0);
  const signature = await pending; assert.equal(signature.kind, 'signature-valid');
  if (signature.kind !== 'signature-valid') throw Error('Expected signature receipt');
  assert.deepEqual(Object.keys(signature.receipt), []); assert.equal(Object.isFrozen(signature.receipt), true);
  const other = await TokenVerifier.prepare(manifest);
  assert.deepEqual(other.checkContext(signature.receipt, 0), { kind: 'rejected', reason: 'authorization-unavailable' });
  assert.equal(verifier.checkContext(signature.receipt, 0).kind, 'claim-candidate');
  assert.deepEqual(verifier.checkContext(signature.receipt, 0), { kind: 'rejected', reason: 'authorization-unavailable' });
});

test('rejects non-byte, truncated, trailing and oversized input', async () => {
  for (const input of [null, undefined, [], 'token', new ArrayBuffer(354), epochZero.subarray(1),
    new Uint8Array([...epochZero, 0]), new Uint8Array(65536)]) {
    assert.deepEqual(await verifier.verify(input, 0), { kind: 'rejected', reason: 'token-malformed' });
  }
});

test('rejects unsupported token type and unknown full key ID before verification', async () => {
  const type = Uint8Array.from(epochZero); type[1] = 1;
  assert.deepEqual(await verifier.verify(type, 0), { kind: 'rejected', reason: 'token-type-unsupported' });
  const key = Uint8Array.from(epochZero); key[66] = key[66]! ^ 1;
  assert.deepEqual(await verifier.verify(key, 0), { kind: 'rejected', reason: 'token-key-unknown' });
});

test('modified nonce, challenge digest and authenticator fail signature verification', async () => {
  for (const offset of [2, 34, 98, 353]) {
    const modified = Uint8Array.from(epochZero); modified[offset] = modified[offset]! ^ 1;
    assert.deepEqual(await verifier.verify(modified, 0), { kind: 'rejected', reason: 'token-invalid' });
  }
});

test('genuinely signed old/future epoch, other run and other origin tokens fail context validation', async () => {
  const mismatch = { kind: 'rejected', reason: 'token-context-mismatch' };
  assert.deepEqual(await verifier.verify(epochZero, 1), mismatch);
  assert.deepEqual(await verifier.verify(epochOne, 0), mismatch);
  const otherRun = { ...manifest, run_id: 'f'.repeat(32) };
  assert.deepEqual(await verifier.verify(await issue(challenge(otherRun, 0)), 0), mismatch);
  const otherOrigin = new TokenChallenge(2, manifest.issuer_name, redemptionContext(manifest, 0), ['other.lab.test']);
  assert.deepEqual(await verifier.verify(await issue(otherOrigin), 0), mismatch);
});

test('independent published token has a valid signature but not this configured lab context', async () => {
  const configured = await TokenVerifier.prepare(golden.manifest);
  assert.deepEqual(await configured.verify(fromHex(known.token, PROTOCOL.token_bytes), 2), {
    kind: 'rejected', reason: 'token-context-mismatch',
  });
});

test('invalid trusted epoch or unsafe arithmetic fails closed without deriving a candidate', async () => {
  for (const epoch of [-1, NaN, Infinity, 0.5, Number.MAX_SAFE_INTEGER]) {
    assert.deepEqual(await verifier.verify(epochZero, epoch), { kind: 'rejected', reason: 'authorization-unavailable' });
  }
});

test('takes owned copies of configuration and incoming pooled buffers', async () => {
  const config = structuredClone(manifest);
  const prepared = TokenVerifier.prepare(config);
  config.run_id = '0'.repeat(32);
  const isolated = await prepared;
  const pool = Buffer.alloc(512, 0xee); pool.set(epochZero, 17);
  const pending = isolated.verify(pool.subarray(17, 17 + PROTOCOL.token_bytes), 0);
  pool.fill(0);
  assert.equal((await pending).kind, 'claim-candidate');
});

test('invalid preparation is rejected with fixed diagnostics and no credential values', async () => {
  await assert.rejects(TokenVerifier.prepare({ ...manifest, token_key_id: '0'.repeat(64), secret: 'do-not-echo' }),
    { message: 'verification-configuration-invalid' });
  const result = await verifier.verify(new Uint8Array(354), 0);
  assert.deepEqual(Object.keys(result).sort(), ['kind', 'reason']);
});
