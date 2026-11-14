import test from 'node:test';
import assert from 'node:assert/strict';
import { createECDH, randomBytes } from 'node:crypto';
import { createServer as createTcpServer } from 'node:net';
import type { Server } from 'node:https';
import { TokenChallenge } from '@cloudflare/privacypass-ts';
import {
  canonicalJson, configurationDigest, encodeBase64Url, hex, makeManifest, PROTOCOL, sha256, voucherDigest,
} from '../../../contracts/lib/index.ts';
import {
  REGIONAL, arcRpcMacInput, encodeRegionalFrame, regionalContext, regionalPolicyDigest, validateArcRequest,
  type ArcRequest, type ArcResponse, type RegionalPolicy,
} from '../../../contracts/lib/regional.ts';
import { checkRegionalMac, decodeCanonicalRegionalJson, regionalMac, regionalType2Challenge } from '../../../contracts/lib/regional-wire.ts';
import { LabIssuer, LabIssuance, verifyTokenSignature } from '../src/protocol.ts';
import { RegionalAdmission } from '../src/issuer/regional.ts';
import { VoucherStore } from '../src/issuer/vouchers.ts';
import { IssuanceService } from '../src/issuer/issuance.ts';
import { createIssuerServer } from '../src/issuer/server.ts';
import { createPki } from './helpers/pki.ts';
import { https, listen } from './helpers/https.ts';

async function setup(count = 5) {
  const signer = await LabIssuer.generate(PROTOCOL.issuer_name);
  const now = Date.now();
  const manifest = makeManifest({ run_id: hex(randomBytes(16)), run_start_ms: now,
    token_key_spki_b64url: encodeBase64Url(signer.publicKeySpki), inventory_total: count,
    snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40) });
  const policy: RegionalPolicy = { contract_version: REGIONAL.contract_version, schema_version: 1,
    run_id: manifest.run_id, baseline_config_digest: configurationDigest(manifest), profile: 'type2-bearer',
    window_start_ms: now, window_end_ms: now + REGIONAL.window_ms, quota: 5, admitted_entitlements: 5,
    resource_id: 'research-resource', method: 'GET', url: 'https://origin.lab.test/resource',
    type2_key_id: manifest.token_key_id, arc_key_id: null, arc_implementation_revision: null, arc_tag_encoding: null };
  const vouchers = Array.from({ length: count }, () => randomBytes(32));
  const store = new VoucherStore(count);
  store.provision({ batch_id: 'a'.repeat(32), batch_index: 0, expected_total: count, final_batch: true, items: vouchers.map(voucherDigest) });
  store.lock();
  const service = new RegionalAdmission({ policy, signer, vouchers: store, now: () => now });
  service.setOpen(true);
  const challenge = TokenChallenge.deserialize(regionalType2Challenge(regionalContext(policy)));
  const issuances = await Promise.all(Array.from({ length: 5 }, () => LabIssuance.begin(challenge, signer.publicKeySpki)));
  const body = (voucher = vouchers[0]!) => ({ contract_version: REGIONAL.contract_version, policy_digest: regionalPolicyDigest(policy),
    profile: policy.profile, enrollment_voucher_b64url: voucher.toString('base64url'),
    blinded_requests_b64url: issuances.map(issuance => encodeBase64Url(issuance.requestWire, false)) });
  return { signer, manifest, policy, vouchers, store, service, issuances, body, now };
}
const wire = (value: unknown) => Buffer.from(canonicalJson(value));

test('one entitlement issues exactly five genuine Type2 signatures and a concurrent duplicate loses', async () => {
  const rig = await setup();
  const replies = await Promise.all([rig.service.handleEnrollment(wire(rig.body())), rig.service.handleEnrollment(wire(rig.body()))]);
  assert.deepEqual(replies.map(reply => reply.status).sort(), [200, 403]);
  assert.equal(rig.service.reservedEntitlements, 1);
  assert.equal(rig.store.remaining, 4);
  const response = JSON.parse(Buffer.from(replies.find(reply => reply.status === 200)!.body).toString()) as { responses_b64url: string[] };
  assert.equal(response.responses_b64url.length, 5);
  for (const [index, issuance] of rig.issuances.entries()) {
    const token = await issuance.finalize(Buffer.from(response.responses_b64url[index]!, 'base64url'));
    assert.equal(await verifyTokenSignature(rig.signer.publicKeySpki, token), true);
  }
  rig.service.setOpen(false);
});

test('canonical framing, exact profile and exact five-request shape are validated before reserving', async () => {
  const rig = await setup();
  const body = rig.body();
  for (const invalid of [Buffer.from(JSON.stringify(body)), Buffer.concat([wire(body), Buffer.from('\n')]),
    wire({ ...body, extra: 1 }), wire({ ...body, profile: 'type2-holder' }),
    wire({ ...body, blinded_requests_b64url: body.blinded_requests_b64url.slice(0, 4) }),
    Buffer.from(canonicalJson(body).replace('{', '{"profile":"type2-bearer",'))]) {
    assert.equal((await rig.service.handleEnrollment(invalid)).status, 400);
  }
  const badRequests = [...body.blinded_requests_b64url];
  const bytes = Buffer.from(badRequests[0]!, 'base64url'); bytes[2] = bytes[2]! ^ 1;
  badRequests[0] = bytes.toString('base64url');
  assert.equal((await rig.service.handleEnrollment(wire({ ...body, blinded_requests_b64url: badRequests }))).status, 422);
  assert.equal(rig.store.remaining, 5);
  assert.equal((await rig.service.handleEnrollment(wire(body))).status, 200);
  rig.service.setOpen(false);
});

test('uncertain partial signing never refunds, and fixed-window boundary cannot renew the wallet', async () => {
  const rig = await setup();
  let calls = 0, now = rig.now;
  const service = new RegionalAdmission({ policy: rig.policy, vouchers: rig.store, now: () => now,
    signer: { publicKeySpki: rig.signer.publicKeySpki, sign: async request => {
      calls++;
      if (calls === 3) throw Error('signer-failed');
      return rig.signer.sign(request);
    } } });
  service.setOpen(true);
  assert.equal((await service.handleEnrollment(wire(rig.body()))).status, 503);
  assert.equal(calls, 3);
  assert.equal((await service.handleEnrollment(wire(rig.body()))).status, 403);
  now = rig.policy.window_end_ms;
  assert.equal((await service.handleEnrollment(wire(rig.body(rig.vouchers[1]!)))).status, 503);
  assert.equal(rig.store.remaining, 4);
  service.setOpen(false);
  assert.throws(() => service.setOpen(true), /closed/);
  assert.throws(() => new RegionalAdmission({ policy: { ...rig.policy, window_end_ms: now + 1 }, signer: rig.signer, vouchers: rig.store }));
});

test('server public canonical enrollment works over TLS and legacy individual issuance is closed for regional runs', async () => {
  const rig = await setup();
  const pki = createPki();
  const baseline = new IssuanceService(rig.signer, rig.store, rig.manifest.limits.issuer);
  baseline.setOpen(true);
  const server = createIssuerServer(baseline, rig.signer.publicKeySpki, pki.leaf(PROTOCOL.issuer_name), rig.service);
  const port = await listen(server);
  try {
    const body = wire(rig.body());
    const result = await https(port, pki.caPem, { method: 'POST', path: '/regional/enroll', body,
      headers: { 'Content-Type': 'application/json', 'Content-Length': String(body.length) } });
    assert.equal(result.status, 200);
    assert.equal(result.headers['cache-control'], 'no-store');
    assert.equal((await https(port, pki.caPem, { method: 'POST', path: '/issue', body: rig.issuances[0]!.requestWire,
      headers: { 'X-Lab-Voucher': rig.vouchers[1]!.toString('base64url') } })).status, 404);
    assert.equal((await https(port, pki.caPem, { method: 'POST', path: '/regional/enroll', body,
      headers: { 'Content-Type': 'text/plain', 'Content-Length': String(body.length) } })).status, 415);
    assert.equal(rig.store.remaining, 4);
  } finally { rig.service.setOpen(false); server.closeAllConnections(); server.close(); }
});

test('ARC enrollment uses one authenticated bounded TCP request and refuses bad reply binding without a refund', async () => {
  const rig = await setup();
  const ecdh = createECDH('prime256v1'); ecdh.generateKeys();
  const params = Buffer.concat(Array.from({ length: 3 }, () => ecdh.getPublicKey(undefined, 'compressed')));
  const policy: RegionalPolicy = { ...rig.policy, profile: 'arc', type2_key_id: null, arc_key_id: hex(sha256(params)),
    arc_implementation_revision: 'a'.repeat(40), arc_tag_encoding: REGIONAL.arc_tag_encoding as 'SEC1-P256-compressed' };
  const bootstrap = { contract_version: REGIONAL.contract_version, run_id: policy.run_id, service_incarnation: 'b'.repeat(32),
    arc_implementation_revision: policy.arc_implementation_revision!, arc_key_id: policy.arc_key_id!, issuer_params_b64url: params.toString('base64url') };
  const key = randomBytes(32);
  let corrupt = false, refuseProof = false, calls = 0, faulted = false;
  const peer = createTcpServer(socket => {
    let bytes = Buffer.alloc(0);
    socket.on('data', chunk => {
      bytes = Buffer.concat([bytes, chunk]);
      if (!bytes.includes(10)) return;
      const frame = decodeCanonicalRegionalJson(bytes, true) as { body: ArcRequest; mac: string };
      validateArcRequest(frame.body, policy);
      assert.equal(checkRegionalMac(key, arcRpcMacInput('request', 'issue', frame.body), frame.mac), true);
      calls++;
      const response = { ...frame.body, request_digest: hex(sha256(wire(frame.body))),
        ...(refuseProof ? { status: 'refused', code: 'invalid-proof' }
          : { status: 'issued', credential_response_b64url: Buffer.from('fixture-response').toString('base64url') }) } as ArcResponse;
      delete (response as unknown as Record<string, unknown>)['grant_id'];
      delete (response as unknown as Record<string, unknown>)['blinded_request_b64url'];
      const mac = regionalMac(key, arcRpcMacInput('response', 'issue', response));
      socket.end(encodeRegionalFrame(response, corrupt ? '0'.repeat(64) : mac));
    });
  });
  const port = await listen(peer as unknown as Server);
  const service = new RegionalAdmission({ policy, signer: rig.signer, vouchers: rig.store, now: () => rig.now,
    arc: { bootstrap, endpoint: { host: '127.0.0.1', port }, issueKey: key }, onFault: () => { faulted = true; } });
  service.setOpen(true);
  const body = (voucher: Buffer) => ({ contract_version: REGIONAL.contract_version, policy_digest: regionalPolicyDigest(policy),
    profile: 'arc', enrollment_voucher_b64url: voucher.toString('base64url'), blinded_requests_b64url: ['AQ'] });
  try {
    assert.equal(service.directory().status, 200);
    assert.equal((await service.handleEnrollment(wire(body(rig.vouchers[0]!)))).status, 200);
    assert.equal((await service.handleEnrollment(wire(body(rig.vouchers[0]!)))).status, 403);
    refuseProof = true;
    assert.equal((await service.handleEnrollment(wire(body(rig.vouchers[1]!)))).status, 403);
    assert.equal((await service.handleEnrollment(wire(body(rig.vouchers[1]!)))).status, 403);
    assert.equal(faulted, false, 'an authenticated invalid proof burns its entitlement and keeps the service available');
    refuseProof = false;
    assert.equal((await service.handleEnrollment(wire(body(rig.vouchers[2]!)))).status, 200);
    corrupt = true;
    assert.equal((await service.handleEnrollment(wire(body(rig.vouchers[3]!)))).status, 503);
    assert.equal(faulted, true);
    assert.equal(calls, 4);
    assert.equal(rig.store.remaining, 1);
    assert.equal((await service.handleEnrollment(wire(body(rig.vouchers[4]!)))).status, 503);
  } finally { service.setOpen(false); peer.close(); }
});
