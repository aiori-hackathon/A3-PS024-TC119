import test from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { WorkerSigner } from '../src/issuer/worker-signer.ts';
import { LabIssuance, challengeFor, verifyTokenSignature } from '../src/protocol.ts';
import { makeManifest, encodeBase64Url, PROTOCOL } from '../../../contracts/lib/index.ts';
import { IssuerRole } from '../src/issuer/control.ts';
import type { IssuerSigner } from '../src/protocol.ts';

const workerUrl = new URL('../src/issuer/signing-worker.ts', import.meta.url);
const manifestFor = (signer: WorkerSigner) => makeManifest({ run_id: '1'.repeat(32), run_start_ms: Date.now(),
  token_key_spki_b64url: encodeBase64Url(signer.publicKeySpki, true), snapshot_script_sha1: '2'.repeat(40), claim_script_sha1: '3'.repeat(40) });

test('real blind signatures run without blocking the issuer control event loop', async t => {
  let failed = false;
  const signer = await WorkerSigner.create(workerUrl, PROTOCOL.issuer_name, () => { failed = true; });
  t.after(() => signer.close());
  const manifest = manifestFor(signer);
  const challenge = challengeFor(manifest, 0);
  const requests = await Promise.all([LabIssuance.begin(challenge, signer.publicKeySpki), LabIssuance.begin(challenge, signer.publicKeySpki)]);
  let ticks = 0, last = performance.now(), worstGap = 0;
  const timer = setInterval(() => {
    const now = performance.now(); worstGap = Math.max(worstGap, now - last); last = now; ticks++;
  }, 10);
  try {
    const responses = await Promise.all(requests.map(r => signer.sign(r.requestWire)));
    worstGap = Math.max(worstGap, performance.now() - last);
    assert.ok(ticks > 0, 'control timers ran while private RSA operations were pending');
    assert.ok(worstGap < 1500, 'control loop stayed within the unchanged heartbeat acknowledgement deadline');
    for (let i = 0; i < requests.length; i++) {
      const token = await requests[i]!.finalize(responses[i]!);
      assert.equal(await verifyTokenSignature(signer.publicKeySpki, token), true);
    }
    assert.equal(failed, false);
  } finally { clearInterval(timer); }
});

test('signer shutdown rejects pending work and is a shared termination barrier', async t => {
  const signer = await WorkerSigner.create(workerUrl, PROTOCOL.issuer_name, () => {});
  t.after(() => signer.close());
  const manifest = manifestFor(signer);
  const request = await LabIssuance.begin(challengeFor(manifest, 0), signer.publicKeySpki);
  const pending = signer.sign(request.requestWire);
  const rejected = assert.rejects(pending, /signer-unavailable/);
  const closed = signer.close();
  assert.equal(signer.close(), closed);
  await Promise.all([closed, rejected]);
  await assert.rejects(signer.sign(request.requestWire), /signer-unavailable/);
});

test('worker failure rejects pending operations, latches one fault and refuses further signs', async t => {
  let faults = 0;
  const signer = await WorkerSigner.create(new URL('./helpers/crashing-signer.ts', import.meta.url), PROTOCOL.issuer_name, () => { faults++; });
  t.after(() => signer.close());
  await assert.rejects(signer.sign(new Uint8Array(PROTOCOL.request_bytes)), /signer-unavailable/);
  await signer.close();
  assert.equal(faults, 1);
  await assert.rejects(signer.sign(new Uint8Array(PROTOCOL.request_bytes)), /signer-unavailable/);
});

test('startup exit and malformed signing replies fail closed', async t => {
  const url = new URL('./helpers/crashing-signer.ts', import.meta.url);
  await assert.rejects(WorkerSigner.create(url, 'startup-exit', () => {}), /signer-unavailable/);
  let faults = 0;
  const signer = await WorkerSigner.create(url, 'invalid-response', () => { faults++; });
  t.after(() => signer.close());
  await assert.rejects(signer.sign(new Uint8Array(PROTOCOL.request_bytes)), /signer-unavailable/);
  await signer.close();
  assert.equal(faults, 1);
});

test('FENCE waits for termination of a signer created after fencing began', async () => {
  let created!: (signer: IssuerSigner) => void, terminate!: () => void;
  let started!: () => void;
  const startedClosing = new Promise<void>(resolve => { started = resolve; });
  const terminated = new Promise<void>(resolve => { terminate = resolve; });
  const role = new IssuerRole({ createSigner: () => new Promise(resolve => { created = resolve; }) });
  const create = role.handle({ version: 1, request_id: '1'.repeat(32), command: 'CREATE_ISSUER_KEY', run_id: '2'.repeat(32),
    config_digest: null, target_incarnation: role.incarnation, payload: {} });
  await new Promise(resolve => setImmediate(resolve));
  let fenced = false;
  const fence = role.handle({ version: 1, request_id: '3'.repeat(32), command: 'FENCE', run_id: null,
    config_digest: null, target_incarnation: null, payload: { reason: 'operator-stop' } }).then(reply => { fenced = true; return reply; });
  created({ publicKeySpki: new Uint8Array(294), sign: async () => new Uint8Array(256),
    close: async () => { started(); await terminated; } });
  await startedClosing;
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(fenced, false);
  terminate();
  assert.equal((await create)['ok'], false);
  assert.equal((await fence)['result'], 'FENCED');
});
