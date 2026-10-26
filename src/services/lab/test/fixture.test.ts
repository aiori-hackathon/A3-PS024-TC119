// Independent consumer derivation of the policy fixture. Uses node:crypto and the PUBLIC data files only
// (protocol-v1.json values, the RFC public key); it deliberately reuses none of the contracts/lib encoders
// and not the Python script, until the final comparison against the shared helpers.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import golden from '../../../contracts/fixtures/policy-golden.json' with { type: 'json' };
import known from '../../../contracts/fixtures/rfc9578-public.json' with { type: 'json' };
import protocol from '../../../contracts/protocol-v1.json' with { type: 'json' };
import * as shared from '../../../contracts/lib/index.ts';

const sha = (b: Buffer | string) => createHash('sha256').update(b).digest();
const u16 = (n: number) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u64 = (n: number) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const lp = (s: string) => Buffer.concat([u16(Buffer.byteLength(s, 'ascii')), Buffer.from(s, 'ascii')]);
// Own sorted-key canonical JSON for ASCII strings, safe nonnegative integers, booleans, null, arrays.
const canon = (v: unknown): string => {
  if (v === null || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'number') { assert.ok(Number.isSafeInteger(v) && v >= 0); return String(v); }
  if (typeof v === 'string') { assert.match(v, /^[\x20-\x7e]*$/); return JSON.stringify(v); }
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  const o = v as Record<string, unknown>;
  return '{' + Object.keys(o).sort().map((k) => JSON.stringify(k) + ':' + canon(o[k])).join(',') + '}';
};

const spki = Buffer.from(known.pkS, 'hex');
const runId = Buffer.from(Array.from({ length: 16 }, (_, i) => i));
const nonce = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const voucher = Buffer.from(Array.from({ length: 32 }, (_, i) => 64 + i));
const epoch = 2, runStart = 1700000000000, epochMs = 600000;
const start = runStart + epoch * epochMs, end = start + epochMs;

// Labels are written out from the plan text, not read from protocol.domains, so a drifted label is caught.
const contextInput = Buffer.concat([Buffer.from('PS024-context-v1'), u16(2), runId, sha(spki), u64(epoch), u64(start), u64(end),
  lp('issuer.lab.test'), lp('origin.lab.test'), lp('GET /resource')]);
const context = sha(contextInput);
const challenge = Buffer.concat([u16(2), lp('issuer.lab.test'), Buffer.from([32]), context, lp('origin.lab.test')]);
const authInput = Buffer.concat([u16(2), nonce, sha(challenge), sha(spki)]);

test('lab-derived bytes and digests equal policy-golden.json', () => {
  assert.equal(golden.epoch, epoch);
  assert.equal(golden.epoch_start_ms, start);
  assert.equal(golden.epoch_end_ms, end);
  assert.equal(golden.manifest.token_key_id, sha(spki).toString('hex'));
  assert.equal(contextInput.toString('hex'), golden.context_input_hex);
  assert.equal(context.toString('hex'), golden.redemption_context_hex);
  assert.equal(challenge.toString('hex'), golden.challenge_hex);
  assert.equal(sha(challenge).toString('hex'), golden.challenge_digest_hex);
  assert.equal(authInput.length, protocol.auth_input_bytes);
  assert.equal(authInput.toString('hex'), golden.auth_input_hex);
  assert.equal(sha(Buffer.concat([Buffer.from('PS024-spend-v1'), authInput])).toString('hex'), golden.spend_id);
  assert.equal(sha(Buffer.concat([Buffer.from('PS024-voucher-v1'), voucher])).toString('hex'), golden.voucher_digest);
  assert.equal(sha(spki).at(-1), golden.truncated_token_key_id);
  assert.equal(nonce.toString('hex'), golden.nonce_hex);
  assert.equal(voucher.toString('hex'), golden.voucher_hex);
});

test('lab-derived manifest, canonical JSON and configuration digest equal the fixture', () => {
  const p = protocol;
  const manifest = {
    schema_version: 1, contract_version: p.contract_version, policy_version: 1,
    run_id: runId.toString('hex'), run_start_ms: runStart, epoch_ms: 600000, guard_ms: 30000, token_type: 2,
    token_key_id: sha(spki).toString('hex'), token_key_spki_b64url: spki.toString('base64').replaceAll('+', '-').replaceAll('/', '_'),
    issuer_name: 'issuer.lab.test', origin_name: 'origin.lab.test', resource_scope: 'GET /resource',
    issuer_request_uri: 'https://issuer.lab.test/issue', snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40),
    gateway_profile: 'B1', client_profile: 'security', inventory_total: 128, endpoints: p.endpoints,
    limits: { gateway: { ...p.gateway_common, ...p.gateway_profiles.B1 }, issuer: p.issuer_limits,
      client: p.client_profiles.security, control_message_max_bytes: 65536, provision_batch_max: 128 },
  };
  assert.deepEqual(manifest, golden.manifest);
  assert.equal(canon(manifest), golden.canonical_manifest);
  assert.equal(sha(canon(manifest)).toString('hex'), golden.config_digest);
  // Literals the plan fixes independently of the data file.
  assert.equal(p.epoch_ms, 600000);
  assert.equal(p.guard_ms, 30000);
  assert.deepEqual([p.request_bytes, p.response_bytes, p.token_bytes, p.auth_input_bytes], [259, 256, 354, 98]);
});

test('shared helpers produce the same bytes as the lab derivation', () => {
  const m = shared.validateManifest(golden.manifest);
  assert.equal(shared.hex(shared.contextInput(m, epoch)), contextInput.toString('hex'));
  assert.equal(shared.hex(shared.challengeBytes(m, epoch)), challenge.toString('hex'));
  assert.equal(shared.configurationDigest(m), sha(canon(m)).toString('hex'));
  assert.equal(shared.spendId(shared.authenticatorInput(nonce, sha(challenge), sha(spki))), golden.spend_id);
  assert.equal(shared.voucherDigest(voucher), golden.voucher_digest);
  assert.equal(shared.CONTRACT_VERSION, readFileSync(new URL('../../../contracts/VERSION', import.meta.url), 'utf8').trim());
});
