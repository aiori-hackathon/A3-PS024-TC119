import test from 'node:test';
import assert from 'node:assert/strict';
import { Token, TOKEN_TYPES } from '@cloudflare/privacypass-ts';
import known from '../../../contracts/fixtures/rfc9578-public.json' with { type: 'json' };
import {
  PROTOCOL, makeManifest, hex, fromHex, sha256, challengeBytes, encodeBase64Url, libraryBytes, tokenWire, type Manifest,
} from '../../../contracts/lib/index.ts';
import { LabIssuer, LabIssuance, challengeFor, verifyTokenSignature } from '../src/protocol.ts';

const manifestFor = (issuer: LabIssuer): Manifest => makeManifest({
  run_id: hex(crypto.getRandomValues(new Uint8Array(16))), run_start_ms: 1700000000000,
  token_key_spki_b64url: encodeBase64Url(issuer.publicKeySpki), snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40),
});

test('independent RFC 9578 public vector verifies with the public key only', async () => {
  const spki = fromHex(known.pkS, known.pkS.length / 2);
  const wire = fromHex(known.token, 354);
  assert.equal(await verifyTokenSignature(spki, wire), true);
  const token = Token.deserialize(TOKEN_TYPES.BLIND_RSA, tokenWire(wire));
  assert.equal(hex(token.authInput.tokenKeyId), hex(sha256(spki)));
  const altered = Uint8Array.from(wire); altered[100] = altered[100]! ^ 1;
  assert.equal(await verifyTokenSignature(spki, altered), false);
});

test('real blind issuance: exact sizes, finalization and public-only verification', async () => {
  const issuer = await LabIssuer.generate(PROTOCOL.issuer_name);
  const m = manifestFor(issuer);
  const issuance = await LabIssuance.begin(challengeFor(m, 0), issuer.publicKeySpki);
  assert.equal(issuance.requestWire.length, PROTOCOL.request_bytes);
  assert.equal(issuance.requestWire[2], sha256(issuer.publicKeySpki).at(-1), 'truncated token key id');
  const response = await issuer.sign(issuance.requestWire);
  assert.equal(response.length, PROTOCOL.response_bytes);
  const token = await issuance.finalize(response);
  assert.equal(token.length, PROTOCOL.token_bytes);
  assert.equal(await verifyTokenSignature(issuer.publicKeySpki, token), true);
  // Signature validity is not context validity: the embedded challenge digest binds epoch 0 only.
  const parsed = Token.deserialize(TOKEN_TYPES.BLIND_RSA, token);
  assert.equal(hex(parsed.authInput.challengeDigest), hex(sha256(challengeBytes(m, 0))));
  assert.notEqual(hex(parsed.authInput.challengeDigest), hex(sha256(challengeBytes(m, 1))));
  const otherRun = { ...m, run_id: 'ff'.repeat(16) };
  assert.notEqual(hex(parsed.authInput.challengeDigest), hex(sha256(challengeBytes(otherRun, 0))));
});

test('a token does not verify under a different issuer key or after bit flips', async () => {
  const a = await LabIssuer.generate(PROTOCOL.issuer_name), b = await LabIssuer.generate(PROTOCOL.issuer_name);
  const issuance = await LabIssuance.begin(challengeFor(manifestFor(a), 0), a.publicKeySpki);
  const token = await issuance.finalize(await a.sign(issuance.requestWire));
  assert.equal(await verifyTokenSignature(a.publicKeySpki, token), true);
  assert.equal(await verifyTokenSignature(b.publicKeySpki, token), false);
  for (const at of [2, 40, 70, 200, 353]) {
    const bad = Uint8Array.from(token); bad[at] = bad[at]! ^ 0x80;
    assert.equal(await verifyTokenSignature(a.publicKeySpki, bad).catch(() => false), false, `offset ${at}`);
  }
});

test('wire views from pooled Buffers are isolated before library parsing', async () => {
  const issuer = await LabIssuer.generate(PROTOCOL.issuer_name);
  const issuance = await LabIssuance.begin(challengeFor(manifestFor(issuer), 0), issuer.publicKeySpki);
  const pooled = Buffer.alloc(600, 0xee); pooled.set(issuance.requestWire, 37);
  const response = await issuer.sign(pooled.subarray(37, 37 + 259));
  const pooledResponse = Buffer.alloc(500, 0xdd); pooledResponse.set(response, 11);
  const token = await issuance.finalize(pooledResponse.subarray(11, 11 + 256));
  const pooledToken = Buffer.alloc(700, 0xcc); pooledToken.set(token, 5);
  assert.equal(await verifyTokenSignature(issuer.publicKeySpki, pooledToken.subarray(5, 5 + 354)), true);
  assert.notEqual(libraryBytes(pooledToken.subarray(5, 359)).buffer, pooledToken.buffer);
});

test('wrong request/response/token sizes are rejected before any library work', async () => {
  const issuer = await LabIssuer.generate(PROTOCOL.issuer_name);
  const issuance = await LabIssuance.begin(challengeFor(manifestFor(issuer), 0), issuer.publicKeySpki);
  for (const n of [0, 258, 260, 4096]) await assert.rejects(issuer.sign(new Uint8Array(n)), { message: 'wire-length' });
  const response = await issuer.sign(issuance.requestWire);
  await assert.rejects(issuance.finalize(response.subarray(0, 255)), { message: 'wire-length' });
  await assert.rejects(verifyTokenSignature(issuer.publicKeySpki, new Uint8Array(353)), { message: 'wire-length' });
  await assert.rejects(verifyTokenSignature(issuer.publicKeySpki, new Uint8Array(355)), { message: 'wire-length' });
  const wrongType = Uint8Array.from(issuance.requestWire); wrongType[0] = 0; wrongType[1] = 1; // token type 1, not 2
  await assert.rejects(issuer.sign(wrongType));
});

test('each outstanding issuance has its own client; finalization is single-use and concurrent issuances are independent', async () => {
  const issuer = await LabIssuer.generate(PROTOCOL.issuer_name);
  const m = manifestFor(issuer);
  const set = await Promise.all([0, 0, 1, 1].map((e) => LabIssuance.begin(challengeFor(m, e), issuer.publicKeySpki)));
  assert.equal(new Set(set.map((i) => hex(i.requestWire))).size, 4, 'blinded requests are all distinct');
  const responses = await Promise.all(set.map((i) => issuer.sign(i.requestWire)));
  const tokens = await Promise.all(set.map((i, n) => i.finalize(responses[n]!)));
  assert.equal(new Set(tokens.map(hex)).size, 4);
  for (const t of tokens) assert.equal(await verifyTokenSignature(issuer.publicKeySpki, t), true);
  await assert.rejects(set[0]!.finalize(responses[0]!), { message: 'issuance-finalized' });
  // Responses are bound to their blinding state: another request's response must not yield a valid token.
  const mismatched = await LabIssuance.begin(challengeFor(m, 0), issuer.publicKeySpki);
  const wrong = await mismatched.finalize(responses[2]!).then((t) => verifyTokenSignature(issuer.publicKeySpki, t), () => false);
  assert.equal(wrong, false);
});
