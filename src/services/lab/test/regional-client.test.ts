// Client integration with a labelled test-local gateway. Production Redis/worker evidence is a separate check.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, randomBytes, verify } from 'node:crypto';
import { createServer } from 'node:https';
import { Token, TOKEN_TYPES } from '@cloudflare/privacypass-ts';
import {
  canonicalJson, configurationDigest, encodeBase64Url, hex, libraryBytes, makeManifest, PROTOCOL, sha256, voucherDigest,
} from '../../../contracts/lib/index.ts';
import {
  REGIONAL, holderContextInput, holderKeyHash, holderNonceMacInput, holderProofInput, regionalContext, regionalPolicyDigest,
  validateRegionalPolicy, type HolderNonce, type HolderProof, type RegionalPolicy,
} from '../../../contracts/lib/regional.ts';
import {
  checkRegionalMac, decodeCanonicalRegionalJson, regionalMac, regionalType2Challenge, validateRegionalPublicRequest,
} from '../../../contracts/lib/regional-wire.ts';
import { LabIssuer, verifyTokenSignature } from '../src/protocol.ts';
import { RegionalAdmission } from '../src/issuer/regional.ts';
import { VoucherStore } from '../src/issuer/vouchers.ts';
import { IssuanceService } from '../src/issuer/issuance.ts';
import { createIssuerServer } from '../src/issuer/server.ts';
import { RegionalClient } from '../src/client/regional.ts';
import { ClientVouchers } from '../src/client/vouchers.ts';
import { ClientRole } from '../src/client/control.ts';
import { createPki } from './helpers/pki.ts';
import { listen } from './helpers/https.ts';
import { startProxy } from './helpers/stubs.ts';

async function setup(profile: 'type2-holder' | 'type2-bearer' | 'ip') {
  const signer = await LabIssuer.generate(PROTOCOL.issuer_name);
  const now = Date.now();
  const manifest = makeManifest({ run_id: hex(randomBytes(16)), run_start_ms: now,
    token_key_spki_b64url: encodeBase64Url(signer.publicKeySpki), inventory_total: 5,
    snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40) });
  const policy = validateRegionalPolicy({ contract_version: REGIONAL.contract_version, schema_version: 1,
    run_id: manifest.run_id, baseline_config_digest: configurationDigest(manifest), profile,
    window_start_ms: now, window_end_ms: now + REGIONAL.window_ms, quota: 5, admitted_entitlements: 5,
    resource_id: 'research-resource', method: 'GET', url: 'https://origin.lab.test/resource',
    type2_key_id: profile === 'ip' ? null : manifest.token_key_id,
    arc_key_id: null, arc_implementation_revision: null, arc_tag_encoding: null }, manifest);
  const vouchers = Array.from({ length: 5 }, () => randomBytes(32));
  const store = new VoucherStore(5);
  store.provision({ batch_id: 'a'.repeat(32), batch_index: 0, expected_total: 5, final_batch: true, items: vouchers.map(voucherDigest) });
  store.lock();
  const service = new RegionalAdmission({ policy, signer, vouchers: store }); service.setOpen(true);
  const baseline = new IssuanceService(signer, store, manifest.limits.issuer); baseline.setOpen(true);
  const pki = createPki();
  const issuer = createIssuerServer(baseline, signer.publicKeySpki, pki.leaf(PROTOCOL.issuer_name), service);
  const issuerPort = await listen(issuer);
  const contextKey = randomBytes(32), nonceKey = randomBytes(32), spent = new Set<string>();
  const publicKeys: string[] = [], signatureLengths: number[] = [];
  let arrivals = 0, requests = 0;
  const digest = regionalPolicyDigest(policy);
  const context = (spki: string) => Buffer.from(regionalMac(contextKey, holderContextInput(policy, spki)), 'hex');
  const gateway = createServer({ ...pki.leaf(PROTOCOL.origin_name), minVersion: 'TLSv1.3' }, async (request, response) => {
    const json = (status: number, value: unknown) => {
      const body = Buffer.from(canonicalJson(value));
      response.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': String(body.length) }); response.end(body);
    };
    const accepted = () => {
      arrivals++;
      const body = Buffer.from('Research resource\nVerified laboratory content.\n');
      response.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': String(body.length) }); response.end(body);
    };
    try {
      requests++;
      if (profile === 'ip') return arrivals < 25 ? accepted() : json(429, { error: 'authorization-refused' });
      if (profile === 'type2-bearer') {
        const auth = request.headers.authorization;
        if (!auth) {
          response.writeHead(401, { 'WWW-Authenticate': `PrivateToken challenge="${encodeBase64Url(regionalType2Challenge(regionalContext(policy)), false)}", token-key="${manifest.token_key_spki_b64url}"`, 'Content-Length': '0' });
          response.end(); return;
        }
        const match = /^PrivateToken token="([A-Za-z0-9_-]+)"$/.exec(auth);
        if (!match) return json(401, { error: 'authorization-refused' });
        const token = Buffer.from(match[1]!, 'base64url'), parsed = Token.deserialize(TOKEN_TYPES.BLIND_RSA, libraryBytes(token));
        if (hex(parsed.authInput.challengeDigest) !== hex(sha256(regionalType2Challenge(regionalContext(policy))))
          || !await verifyTokenSignature(signer.publicKeySpki, token) || spent.has(match[1]!)) return json(401, { error: 'authorization-refused' });
        spent.add(match[1]!); return accepted();
      }
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(chunk as Buffer);
      const route = request.url === '/regional/holder/challenge' ? 'holder-challenge'
        : request.url === '/regional/holder/nonce' ? 'holder-nonce' : 'holder-redeem';
      const body = validateRegionalPublicRequest(route, decodeCanonicalRegionalJson(Buffer.concat(chunks)), policy);
      if (route === 'holder-challenge') {
        const spki = body['public_key_spki_b64url'] as string; publicKeys.push(spki);
        return json(200, { contract_version: REGIONAL.contract_version, policy_digest: digest,
          challenge_b64url: encodeBase64Url(regionalType2Challenge(context(spki)), false),
          token_key_spki_b64url: encodeBase64Url(signer.publicKeySpki, false) });
      }
      if (route === 'holder-nonce') {
        const issued = Date.now();
        const nonce: HolderNonce = { contract_version: REGIONAL.contract_version, run_id: policy.run_id, policy_digest: digest,
          token_hash: body['token_hash'] as string, holder_key_hash: holderKeyHash(body['public_key_spki_b64url'] as string),
          issued_ms: issued, expires_ms: issued + REGIONAL.nonce_lifetime_ms, random_b64url: randomBytes(32).toString('base64url') };
        return json(200, { body: nonce, mac: regionalMac(nonceKey, holderNonceMacInput(nonce)) });
      }
      const token = Buffer.from(body['token_b64url'] as string, 'base64url'), proof = body['proof'] as HolderProof;
      const signature = Buffer.from(proof.signature_b64url, 'base64url'); signatureLengths.push(signature.length);
      const publicKey = createPublicKey({ key: Buffer.from(proof.public_key_spki_b64url, 'base64url'), format: 'der', type: 'spki' });
      const parsed = Token.deserialize(TOKEN_TYPES.BLIND_RSA, libraryBytes(token));
      if (!checkRegionalMac(nonceKey, holderNonceMacInput(proof.nonce.body), proof.nonce.mac)
        || !verify('sha256', holderProofInput(policy, token, proof.public_key_spki_b64url, proof.nonce, Date.now()),
          { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature)
        || hex(parsed.authInput.challengeDigest) !== hex(sha256(regionalType2Challenge(context(proof.public_key_spki_b64url))))
        || !await verifyTokenSignature(signer.publicKeySpki, token) || spent.has(hex(sha256(token)))) {
        return json(401, { error: 'authorization-refused' });
      }
      spent.add(hex(sha256(token))); return accepted();
    } catch { return json(400, { error: 'token-invalid' }); }
  });
  const gatewayPort = await listen(gateway);
  const proxy = await startProxy({ 'issuer.lab.test:443': issuerPort, 'origin.lab.test:443': gatewayPort });
  const clients: RegionalClient[] = [];
  const client = (index = 0, caPem = pki.caPem) => {
    const inventory = new ClientVouchers(1);
    inventory.provision({ batch_id: 'c'.repeat(32), batch_index: 0, expected_total: 1, final_batch: true, items: [vouchers[index]!.toString('base64url')] });
    inventory.lock();
    const value = new RegionalClient({ manifest, policy, vouchers: inventory, proxy: { host: '127.0.0.1', port: proxy.port }, caPem });
    clients.push(value); return value;
  };
  return { policy, manifest, client, service, store, publicKeys, signatureLengths, proxy, vouchers, caPem: pki.caPem,
    arrivals: () => arrivals, requests: () => requests,
    stop() { for (const value of clients) value.close(); service.setOpen(false); issuer.closeAllConnections(); issuer.close();
      gateway.closeAllConnections(); gateway.close(); proxy.server.close(); } };
}

test('holder client uses five per-token P256 keys and P1363 proofs, theft refusal leaves owner usable, fresh-token race has one winner', async () => {
  const rig = await setup('type2-holder');
  try {
    const client = rig.client();
    await client.acquire();
    assert.equal(new Set(rig.publicKeys).size, 5);
    assert.equal(client.estimatedRemaining, 5);
    assert.equal(rig.service.reservedEntitlements, 1);
    assert.equal(client.measurements.preparation_interactions, 5);
    assert.equal((await client.attack()).status, 401);
    assert.equal(rig.arrivals(), 0);
    assert.equal(client.estimatedRemaining, 5);
    const owner = await client.access();
    assert.equal(owner.status, 200);
    assert.match(Buffer.from(owner.resource_b64url!, 'base64url').toString(), /Research resource/);
    assert.equal(rig.arrivals(), 1);
    assert.equal((await client.copyAccess()).status, 401);
    const race = await client.race(20);
    assert.equal(race.filter(result => result.status === 200).length, 1);
    assert.equal(rig.arrivals(), 2);
    assert.ok(rig.signatureLengths.every(length => length === 64));
    assert.equal(client.estimatedRemaining, 3);
    assert.doesNotThrow(() => canonicalJson({ measurements: client.measurements, result: owner }));
    await assert.rejects(client.acquire(), /already-attempted/);
  } finally { rig.stop(); }
});

test('ordinary Type2 acquires five from one voucher and sends all 26 abuse attempts over the verified shared proxy', async () => {
  const rig = await setup('type2-bearer');
  try {
    const client = rig.client();
    await client.acquire();
    const before = rig.requests();
    const results = await client.abuse(26);
    assert.equal(results.length, 26);
    assert.equal(rig.requests() - before, 26);
    assert.equal(results.filter(result => result.status === 200).length, 5);
    assert.equal(rig.arrivals(), 5);
    assert.equal(client.estimatedRemaining, 0);
    await assert.rejects(client.access(), /no-token/);
    assert.equal(client.measurements.issuance_interactions, 1);
    assert.equal(client.measurements.preparation_interactions, 1);
    assert.ok(client.measurements.issuance_request_bytes > 5 * 259, 'actual canonical HTTP body includes base64 and enrollment envelope');
    assert.ok(client.measurements.issuance_response_bytes > 5 * 256);
    assert.deepEqual([...new Set(rig.proxy.connects)].sort(), ['issuer.lab.test:443', 'origin.lab.test:443']);
  } finally { rig.stop(); }
});

test('IP comparison sends the full 26-request workload, 25 reach its test resource and no enrollment is granted', async () => {
  const rig = await setup('ip');
  try {
    const results = await rig.client().abuse(26);
    assert.equal(results.filter(result => result.status === 200).length, 25);
    assert.equal(results[25]!.status, 429);
    assert.equal(rig.service.reservedEntitlements, 0);
  } finally { rig.stop(); }
});

test('wrong CA fails before enrollment and a copied unused voucher cannot refill a second wallet', async () => {
  const rig = await setup('type2-bearer');
  try {
    const bad = rig.client(1, createPki('Untrusted').caPem);
    await assert.rejects(bad.acquire());
    assert.equal(rig.service.reservedEntitlements, 0);
    const owner = rig.client(); await owner.acquire();
    const copy = rig.client(); await assert.rejects(copy.acquire(), /refused/);
    assert.equal(rig.service.reservedEntitlements, 1);
    assert.equal(rig.store.remaining, 4);
    assert.equal((await owner.access()).status, 200);
  } finally { rig.stop(); }
});

test('regional private role installation obeys readiness and fixed actions share the existing FENCE lifecycle', async () => {
  const rig = await setup('type2-holder');
  const role = new ClientRole({ readSecret: () => Buffer.from(rig.caPem), proxy: { host: '127.0.0.1', port: rig.proxy.port } });
  const digest = configurationDigest(rig.manifest);
  const send = (command: string, payload: Record<string, unknown> = {}) => role.handle({ version: 1,
    request_id: randomBytes(16).toString('hex'), command, run_id: rig.manifest.run_id,
    config_digest: command === 'PREPARE_RUN' ? null : digest, target_incarnation: role.incarnation, payload });
  try {
    assert.throws(() => role.installRegional({ policy: rig.policy }), /ILLEGAL_STATE/);
    assert.equal((await send('PREPARE_RUN', { manifest: rig.manifest, proposed_config_digest: digest, role: 'client',
      role_config: { client_id: 'A', ca_cert_path: '/run/secrets/ca.crt' } }))['ok'], true);
    await send('PROVISION_CLIENT', { batch_id: 'a'.repeat(32), batch_index: 0, expected_total: 1, final_batch: true,
      items: [rig.vouchers[0]!.toString('base64url')] });
    role.installRegional({ policy: rig.policy });
    assert.throws(() => role.installRegional({ policy: rig.policy }), /ILLEGAL_STATE/);
    await assert.rejects(role.regionalAction('acquire'), /ILLEGAL_STATE/);
    await send('CHECK_READY'); await send('ENABLE');
    assert.throws(() => role.installRegional({ policy: rig.policy }), /ILLEGAL_STATE/);
    const acquired = await role.regionalAction('acquire');
    assert.equal(acquired['estimated_remaining'], 5);
    const attack = await role.regionalAction('attack');
    assert.equal((attack['results'] as { status: number }[])[0]!.status, 401);
    const owner = await role.regionalAction('access');
    assert.equal((owner['results'] as { status: number }[])[0]!.status, 200);
    assert.doesNotThrow(() => canonicalJson(owner));
    const report = await send('REPORT');
    assert.deepEqual((report['data'] as Record<string, unknown>)['counters'], { issuance_successes: 5, issuance_failures: 0, observations: 2 });
    assert.equal((await send('RUN_SCENARIO', { scenario_id: 'healthy-flow', schedule_seed: 1 }))['ok'], false);
    assert.equal((await send('FENCE', { reason: 'test-cleanup' }))['ok'], true);
    await assert.rejects(role.regionalAction('access'), /ILLEGAL_STATE/);
    assert.equal(role.regionalStatus()['estimated_remaining'], 0);
  } finally { await send('FENCE', { reason: 'test-cleanup' }); rig.stop(); }
});
