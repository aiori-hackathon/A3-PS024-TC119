// Opt-in native Rust interoperability. This proves the adapters and cryptography against a labelled test gateway.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { connect, createServer as tcpServer } from 'node:net';
import { createServer, type Server } from 'node:https';
import { fileURLToPath } from 'node:url';
import {
  canonicalJson, configurationDigest, encodeBase64Url, hex, makeManifest, PROTOCOL, voucherDigest,
} from '../../../contracts/lib/index.ts';
import {
  REGIONAL, arcRpcMacInput, encodeRegionalFrame, regionalPolicyDigest, type ArcRequest, type RegionalPolicy,
} from '../../../contracts/lib/regional.ts';
import {
  authenticateArcResponse, decodeCanonicalRegionalJson, decodeRegionalPublicRequest, regionalMac, validateArcBootstrap,
} from '../../../contracts/lib/regional-wire.ts';
import { LabIssuer } from '../src/protocol.ts';
import { RegionalAdmission } from '../src/issuer/regional.ts';
import { VoucherStore } from '../src/issuer/vouchers.ts';
import { IssuanceService } from '../src/issuer/issuance.ts';
import { createIssuerServer } from '../src/issuer/server.ts';
import { RegionalClient } from '../src/client/regional.ts';
import { ProcessArcClientHelper } from '../src/client/arc-helper.ts';
import { ClientVouchers } from '../src/client/vouchers.ts';
import { createPki } from './helpers/pki.ts';
import { listen } from './helpers/https.ts';
import { startProxy } from './helpers/stubs.ts';

const executable = (name: string) => fileURLToPath(new URL(`../../arc/target/debug/${name}${process.platform === 'win32' ? '.exe' : ''}`, import.meta.url));
const enabled = process.env['TF_ARC_RUNTIME_TEST'] === '1' && existsSync(executable('arc-service')) && existsSync(executable('arc-client-helper'));

test('Node admission and opaque helper interoperate with actual Rust issue/verify, regenerated proofs retain spend identity', { skip: !enabled }, async () => {
  const revision = process.env['TF_ARC_IMPLEMENTATION_REVISION'];
  assert.match(revision ?? '', /^[0-9a-f]{40}$/, 'provide the actual compiled source revision');
  const child = spawn(executable('arc-service'), [], { stdio: 'pipe', windowsHide: true });
  child.stderr.resume();
  let incoming = Buffer.alloc(0);
  let pending: ((value: unknown) => void) | undefined;
  child.stdout.on('data', (chunk: Buffer) => {
    incoming = Buffer.concat([incoming, chunk]);
    if (!incoming.includes(10)) return;
    const value = decodeCanonicalRegionalJson(incoming, true);
    incoming = Buffer.alloc(0);
    const resolve = pending; pending = undefined; resolve?.(value);
  });
  let chain: Promise<unknown> = Promise.resolve();
  const command = (body: unknown): Promise<Record<string, unknown>> => {
    const operation = chain.then(() => new Promise<Record<string, unknown>>((resolve, reject) => {
      const timeout = setTimeout(() => { pending = undefined; reject(Error('service-timeout')); }, 5000);
      pending = value => { clearTimeout(timeout); resolve(value as Record<string, unknown>); };
      child.stdin.write(canonicalJson(body) + '\n');
    }));
    chain = operation.catch(() => undefined);
    return operation;
  };
  const freePort = async () => {
    const server = tcpServer();
    const port = await listen(server as unknown as Server);
    await new Promise<void>(resolve => server.close(() => resolve()));
    return port;
  };
  const issuePort = await freePort(), verifyPort = await freePort();
  const issueKey = randomBytes(32), verifyKey = randomBytes(32), runId = randomBytes(16).toString('hex');
  let timer: NodeJS.Timeout | undefined;
  let client: RegionalClient | undefined;
  let service: RegionalAdmission | undefined;
  let issuer: Server | undefined, gateway: Server | undefined;
  let proxy: Awaited<ReturnType<typeof startProxy>> | undefined;
  try {
    const bootstrap = validateArcBootstrap(await command({ operation: 'bootstrap', run_id: runId, implementation_revision: revision,
      issue_listen: `127.0.0.1:${issuePort}`, verify_listen: `127.0.0.1:${verifyPort}`,
      issue_key: issueKey.toString('hex'), verify_key: verifyKey.toString('hex') }), { run_id: runId, arc_implementation_revision: revision! });
    const signer = await LabIssuer.generate(PROTOCOL.issuer_name);
    const now = Date.now();
    const manifest = makeManifest({ run_id: runId, run_start_ms: now, token_key_spki_b64url: encodeBase64Url(signer.publicKeySpki),
      snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40), inventory_total: 5 });
    const policy: RegionalPolicy = { contract_version: REGIONAL.contract_version, schema_version: 1, run_id: runId,
      baseline_config_digest: configurationDigest(manifest), profile: 'arc', window_start_ms: now, window_end_ms: now + REGIONAL.window_ms,
      quota: 5, admitted_entitlements: 5, resource_id: 'research-resource', method: 'GET', url: 'https://origin.lab.test/resource',
      type2_key_id: null, arc_key_id: bootstrap.arc_key_id, arc_implementation_revision: revision!, arc_tag_encoding: 'SEC1-P256-compressed' };
    assert.equal((await command({ operation: 'install-policy', policy }))['status'], 'installed');
    assert.equal((await command({ operation: 'enable', lease_sequence: 0, lease_expires_ms: Date.now() + 2900 }))['status'], 'enabled');
    let sequence = 0;
    timer = setInterval(() => { void command({ operation: 'heartbeat', lease_sequence: ++sequence, lease_expires_ms: Date.now() + 2900 }); }, 1000);
    const vouchers = Array.from({ length: 5 }, () => randomBytes(32));
    const store = new VoucherStore(5);
    store.provision({ batch_id: 'a'.repeat(32), batch_index: 0, expected_total: 5, final_batch: true, items: vouchers.map(voucherDigest) }); store.lock();
    service = new RegionalAdmission({ policy, signer, vouchers: store,
      arc: { bootstrap, endpoint: { host: '127.0.0.1', port: issuePort }, issueKey } }); service.setOpen(true);
    const malformed = Buffer.from(canonicalJson({ contract_version: REGIONAL.contract_version,
      policy_digest: regionalPolicyDigest(policy), profile: 'arc', enrollment_voucher_b64url: vouchers[4]!.toString('base64url'),
      blinded_requests_b64url: ['AQ'] }));
    assert.equal((await service.handleEnrollment(malformed)).status, 403);
    assert.equal((await service.handleEnrollment(malformed)).status, 403);
    const pki = createPki();
    issuer = createIssuerServer(new IssuanceService(signer, store, manifest.limits.issuer), signer.publicKeySpki, pki.leaf(PROTOCOL.issuer_name), service);
    const issuerPort = await listen(issuer);
    const tags = new Set<string>(), proofs: string[] = [];
    let arrivals = 0;
    gateway = createServer({ ...pki.leaf(PROTOCOL.origin_name), minVersion: 'TLSv1.3' }, async (request, response) => {
      try {
        const chunks: Buffer[] = [];
        for await (const chunk of request) chunks.push(chunk as Buffer);
        const body = decodeRegionalPublicRequest('arc-redeem', Buffer.concat(chunks), policy);
        const presentation = body['presentation_b64url'] as string; proofs.push(presentation);
        const rpc: ArcRequest = { contract_version: REGIONAL.contract_version, run_id: runId,
          policy_digest: regionalPolicyDigest(policy), request_id: randomBytes(16).toString('hex'), service_incarnation: bootstrap.service_incarnation,
          operation: 'verify', presentation_b64url: presentation };
        const wire = await new Promise<Uint8Array>((resolve, reject) => {
          const socket = connect(verifyPort, '127.0.0.1'); let data = Buffer.alloc(0);
          socket.setTimeout(REGIONAL.arc_rpc_timeout_ms, () => socket.destroy(Error('rpc-timeout')));
          socket.once('connect', () => socket.write(encodeRegionalFrame(rpc, regionalMac(verifyKey, arcRpcMacInput('request', 'verify', rpc)))));
          socket.on('data', (chunk: Buffer) => { data = Buffer.concat([data, chunk]); if (data.includes(10)) { socket.destroy(); resolve(data); } });
          socket.on('error', reject);
        });
        const result = authenticateArcResponse(wire, rpc, policy, verifyKey);
        if (result.status !== 'verified' || tags.has(result.spend_tag_b64url)) {
          const body = Buffer.from(canonicalJson({ error: 'authorization-refused' }));
          response.writeHead(401, { 'Content-Type': 'application/json', 'Content-Length': String(body.length) }); response.end(body); return;
        }
        tags.add(result.spend_tag_b64url); arrivals++;
        response.writeHead(200, { 'Content-Length': '8' }); response.end('research');
      } catch { response.writeHead(503, { 'Content-Length': '0' }); response.end(); }
    });
    proxy = await startProxy({ 'issuer.lab.test:443': issuerPort, 'origin.lab.test:443': await listen(gateway) });
    const inventory = new ClientVouchers(1);
    inventory.provision({ batch_id: 'b'.repeat(32), batch_index: 0, expected_total: 1, final_batch: true, items: [vouchers[0]!.toString('base64url')] }); inventory.lock();
    client = new RegionalClient({ manifest, policy, vouchers: inventory, proxy: { host: '127.0.0.1', port: proxy.port }, caPem: pki.caPem,
      arcHelper: new ProcessArcClientHelper(executable('arc-client-helper')) });
    await client.acquire();
    assert.equal(service.reservedEntitlements, 2);
    assert.equal((await client.access()).status, 200);
    assert.equal((await client.copyAccess()).status, 401);
    assert.notEqual(proofs[0], proofs[1]);
    assert.equal(arrivals, 1);
    assert.equal((await client.attack()).status, 401);
    for (let index = 1; index < 5; index++) assert.equal((await client.access()).status, 200);
    assert.equal(arrivals, 5);
    assert.equal(tags.size, 5);
    assert.equal((await client.copyAccess()).status, 401);
    await assert.rejects(client.access(), /no-token/);
    assert.equal(client.measurements.issuance_interactions, 1);
  } finally {
    clearInterval(timer);
    client?.close(); await client?.drain(); service?.setOpen(false);
    issuer?.closeAllConnections(); issuer?.close(); gateway?.closeAllConnections(); gateway?.close(); proxy?.server.close();
    child.kill();
  }
});
