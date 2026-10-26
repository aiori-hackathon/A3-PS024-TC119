import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { publicVerif, TokenChallenge } from '@cloudflare/privacypass-ts';
import { configurationDigest, encodeBase64Url, hex, makeManifest, redemptionContext } from '../../../contracts/lib/index.ts';

test('built verifier is a standalone project bundle and validates a fresh token', async () => {
  const directory = new URL('../dist/', import.meta.url);
  assert.deepEqual(readdirSync(directory).sort(), ['bootstrap.mjs', 'http-auth.mjs', 'token-verifier.mjs']);
  const source = readFileSync(new URL('token-verifier.mjs', directory), 'utf8');
  assert.doesNotMatch(source, /policy-golden|rfc9578-public|services[\\/]lab/);
  const { TokenVerifier } = await import(new URL('token-verifier.mjs', directory).href);
  const mode = publicVerif.BlindRSAMode.PSS;
  const keys = await publicVerif.Issuer.generateKey(mode, { modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) });
  const spki = await publicVerif.getPublicKeyBytes(keys.publicKey);
  const manifest = makeManifest({
    run_id: hex(crypto.getRandomValues(new Uint8Array(16))), run_start_ms: 1700000000000,
    token_key_spki_b64url: encodeBase64Url(spki), snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40),
  });
  const client = new publicVerif.Client(mode);
  const request = await client.createTokenRequest(new TokenChallenge(2, manifest.issuer_name, redemptionContext(manifest, 0), [manifest.origin_name]), spki);
  const token = await client.finalize(await new publicVerif.Issuer(mode, manifest.issuer_name, keys.privateKey, keys.publicKey).issue(request));
  const verifier = await TokenVerifier.prepare(manifest);
  assert.equal((await verifier.verify(token.serialize(), 0)).kind, 'claim-candidate');
  assert.deepEqual(await verifier.verify(token.serialize(), 1), { kind: 'rejected', reason: 'token-context-mismatch' });
  const { parseAuthorization, GatewayResponses } = await import(new URL('http-auth.mjs', directory).href);
  const parsed = parseAuthorization(['Authorization', `PrivateToken token="${encodeBase64Url(token.serialize())}"`]);
  assert.equal(parsed.kind, 'token');
  assert.equal((await verifier.verify(parsed.wire, 0)).kind, 'claim-candidate');
  const snapshot = ['SNAPSHOT', manifest.run_id, manifest.token_key_id, configurationDigest(manifest),
    manifest.run_start_ms, 0, manifest.run_start_ms, manifest.run_start_ms + manifest.epoch_ms];
  const response = GatewayResponses.prepare(manifest).rejection('token-required', snapshot);
  assert.equal(response.status, 401);
  assert.match(response.headers['www-authenticate'], /^PrivateToken challenge="/);
});
