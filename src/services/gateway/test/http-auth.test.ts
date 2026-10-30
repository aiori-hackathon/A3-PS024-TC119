import test from 'node:test';
import assert from 'node:assert/strict';
import { WWWAuthenticateHeader } from '@cloudflare/privacypass-ts';
import golden from '../../../contracts/fixtures/policy-golden.json' with { type: 'json' };
import known from '../../../contracts/fixtures/rfc9578-public.json' with { type: 'json' };
import {
  PROTOCOL, configurationDigest, encodeBase64Url, fromHex, hex, validateManifest,
} from '../../../contracts/lib/index.ts';
import { GatewayResponses, parseAuthorization, type GatewayError } from '../src/http-auth.ts';
import { TokenVerifier } from '../src/token-verifier.ts';

const wire = fromHex(known.token, PROTOCOL.token_bytes);
const encoded = encodeBase64Url(wire);
const auth = `PrivateToken token="${encoded}"`;
const manifest = validateManifest(golden.manifest);
const snapshot = ['SNAPSHOT', manifest.run_id, manifest.token_key_id, configurationDigest(manifest),
  golden.epoch_start_ms + 1, golden.epoch, golden.epoch_start_ms, golden.epoch_end_ms];
const responses = GatewayResponses.prepare(manifest);
const malformed = { kind: 'rejected', reason: 'token-malformed' };
const badRequest = { kind: 'rejected', reason: 'request-malformed' };
function parses(value: string) {
  const result = parseAuthorization(['Authorization', value]);
  assert.equal(result.kind, 'token');
  if (result.kind === 'token') assert.equal(hex(result.wire), known.token);
}

test('missing or another authentication scheme requests a PrivateToken challenge', () => {
  assert.deepEqual(parseAuthorization([]), { kind: 'missing' });
  assert.deepEqual(parseAuthorization(['Host', 'origin.lab.test']), { kind: 'missing' });
  assert.deepEqual(parseAuthorization(['Authorization', 'Bearer opaque']), { kind: 'missing' });
});

test('accepts quoted/unquoted token values, case-insensitive names and HTTP whitespace', () => {
  parses(auth);
  parses(`privatetoken TOKEN=${encoded}`);
  parses(` \tPRIVATETOKEN  \tToKeN \t= \t"${encoded}" \t`);
  const result = parseAuthorization(['aUtHoRiZaTiOn', auth]);
  assert.equal(result.kind, 'token');
});

test('quoted pairs decode before semantic validation; quoted commas do not split parameters', () => {
  parses(`PrivateToken unknown="a,b\\\"c\\\\d", token="\\${encoded[0]}${encoded.slice(1)}"`);
  parses(`PrivateToken token=${encoded}, future="", opaque="\xff"`);
});

test('tolerates bounded empty list members without accepting an empty credential', () => {
  parses(`PrivateToken ,,token=${encoded},,`);
  parses(`PrivateToken ${','.repeat(8)}token=${encoded}`);
  parses(`PrivateToken token=${encoded}${','.repeat(8)}`);
  assert.deepEqual(parseAuthorization(['Authorization', `PrivateToken ${','.repeat(9)}token=${encoded}`]), malformed);
  assert.deepEqual(parseAuthorization(['Authorization', `PrivateToken token=${encoded}${','.repeat(9)}`]), malformed);
  assert.deepEqual(parseAuthorization(['Authorization', 'PrivateToken ,,,']), malformed);
});

test('rejects duplicate raw Authorization fields even with different casing or empty values', () => {
  for (const first of [auth, '', 'Bearer opaque']) {
    assert.deepEqual(parseAuthorization(['Authorization', first, 'authorization', auth]), malformed);
  }
});

test('rejects duplicate parameters and combined credentials rather than selecting one', () => {
  for (const value of [`${auth}, TOKEN=${encoded}`, `${auth}, x=a, X=b`, `${auth}, PrivateToken token=${encoded}`,
    `${auth}, Bearer opaque`, `PrivateToken token=${encoded} token=${encoded}`]) {
    assert.deepEqual(parseAuthorization(['Authorization', value]), malformed);
  }
});

test('refuses malformed quoting, separators, missing values and bare token68 credentials', () => {
  for (const value of ['', 'PrivateToken', 'PrivateToken\ttoken=x', 'PrivateToken x=y',
    'PrivateToken token="', 'PrivateToken token="abc\\', 'PrivateToken token=',
    `PrivateToken ${encoded}`, `${auth}; x=y`, `${auth}garbage`, 'PrivateToken token=""']) {
    assert.deepEqual(parseAuthorization(['Authorization', value]), malformed);
  }
});

test('requires canonical base64url and exactly the Type 2 wire length', () => {
  for (const value of [`${encoded}=`, encoded.slice(1), encoded.slice(0, -1) + '+',
    encodeBase64Url(new Uint8Array(353)), encodeBase64Url(new Uint8Array(355))]) {
    assert.deepEqual(parseAuthorization(['Authorization', `PrivateToken token="${value}"`]), malformed);
  }
});

test('HTTP framing and injection hazards fail before credential parsing', () => {
  for (const input of [null, {}, ['Authorization'], ['Bad Name', 'x'], ['Host', 1],
    ['Authorization', auth + '\r\nX-Injected: yes'], ['X', '\u0000'], ['X', '\u007f'], ['X', '\u0100']]) {
    assert.deepEqual(parseAuthorization(input), badRequest);
  }
});

test('enforces total field count and octet budget before scanning large field contents', () => {
  const fields = Array.from({ length: 31 }, (_, i) => [`X-${i}`, 'a']).flat();
  assert.equal(parseAuthorization([...fields, 'Authorization', auth]).kind, 'token');
  assert.deepEqual(parseAuthorization([...fields, 'Authorization', auth, 'Extra', 'a']), badRequest);
  const base = 2 + 'Authorization'.length + auth.length + 4 + 'X-Pad'.length + 4;
  const padding = 'a'.repeat(PROTOCOL.gateway_common.headers_max_bytes - base);
  assert.equal(parseAuthorization(['Authorization', auth, 'X-Pad', padding]).kind, 'token');
  assert.deepEqual(parseAuthorization(['Authorization', auth, 'X-Pad', padding + 'a']), badRequest);
});

test('parser returns owned credential bytes; unsupported type classification stays with verifier', async () => {
  const input = ['Authorization', auth];
  const result = parseAuthorization(input);
  input[1] = 'changed';
  assert.equal(result.kind, 'token');
  if (result.kind === 'token') {
    assert.equal(result.wire.byteOffset, 0);
    assert.equal(result.wire.buffer.byteLength, PROTOCOL.token_bytes);
    assert.equal(hex(result.wire), known.token);
  }
  const unsupported = Uint8Array.from(wire); unsupported[1] = 1;
  const parsed = parseAuthorization(['Authorization', `PrivateToken token="${encodeBase64Url(unsupported)}"`]);
  assert.equal(parsed.kind, 'token');
  if (parsed.kind === 'token') {
    assert.deepEqual(await (await TokenVerifier.prepare(manifest)).verify(parsed.wire, 2), {
      kind: 'rejected', reason: 'token-type-unsupported',
    });
  }
});

test('every 401 includes a matching shared challenge and public key; no clearance cookie', () => {
  for (const [label, status] of Object.entries(PROTOCOL.gateway_results)) {
    if (status !== 401) continue;
    const response = responses.rejection(label as GatewayError, snapshot);
    assert.equal(response.status, 401);
    const parsed = WWWAuthenticateHeader.parse(response.headers['www-authenticate']!);
    assert.equal(parsed.length, 1);
    assert.equal(hex(parsed[0]!.challenge.serialize()), golden.challenge_hex);
    assert.equal(hex(parsed[0]!.tokenKey), known.pkS);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.equal(response.headers['set-cookie'], undefined);
    assert.deepEqual(JSON.parse(response.body), { error: label });
    assert.equal(Number(response.headers['content-length']), Buffer.byteLength(response.body));
  }
});

test('absent, unsafe, wrong-run/config and malformed snapshots produce 503 without a challenge', () => {
  for (const reply of [undefined, null, ['CLOCK_UNSAFE'], ['RUN_UNAVAILABLE'], [...snapshot, 1],
    snapshot.map((v, i) => i === 1 ? '0'.repeat(32) : v), snapshot.map((v, i) => i === 3 ? '0'.repeat(64) : v),
    snapshot.map((v, i) => i === 5 ? 3 : v)]) {
    const response = responses.rejection('token-invalid', reply);
    assert.equal(response.status, 503);
    assert.equal(response.body, '{"error":"authorization-unavailable"}');
    assert.equal(response.headers['www-authenticate'], undefined);
  }
});

test('non-401 local errors retain their fixed mapping, no-store policy and Allow on 405', () => {
  for (const [reason, status] of Object.entries(PROTOCOL.gateway_results)) {
    if (status === 401) continue;
    const response = responses.rejection(reason as GatewayError);
    assert.equal(response.status, status);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.equal(response.headers['www-authenticate'], undefined);
    assert.equal(response.headers['allow'], status === 405 ? 'GET' : undefined);
    assert.deepEqual(JSON.parse(response.body), { error: reason });
    assert.ok(Object.isFrozen(response.headers));
  }
});

test('response configuration is isolated, unknown error labels cannot be reflected', () => {
  const config = structuredClone(manifest);
  const prepared = GatewayResponses.prepare(config);
  config.run_id = 'f'.repeat(32);
  assert.equal(prepared.rejection('token-required', snapshot).status, 401);
  assert.equal(prepared.rejection('secret-input' as GatewayError).body, '{"error":"authorization-unavailable"}');
  assert.throws(() => GatewayResponses.prepare({ ...manifest, secret: 'do-not-echo' }), { message: 'response-configuration-invalid' });
});

test('header to verifier to rejection path rejects a genuine wrong-context token without echoing it', async () => {
  const parsed = parseAuthorization(['Authorization', auth]);
  assert.equal(parsed.kind, 'token');
  if (parsed.kind !== 'token') return;
  const result = await (await TokenVerifier.prepare(manifest)).verify(parsed.wire, 2);
  assert.equal(result.kind, 'rejected');
  if (result.kind !== 'rejected') return;
  const response = responses.rejection(result.reason, snapshot);
  assert.equal(response.status, 401);
  assert.equal(response.body, '{"error":"token-context-mismatch"}');
  assert.equal(JSON.stringify(response).includes(encoded), false);
});
