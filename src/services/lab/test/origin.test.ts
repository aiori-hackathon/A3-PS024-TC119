import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { request } from 'node:http';
import { connect } from 'node:net';
import { configurationDigest, hex, makeManifest, validateControlResponse } from '../../../contracts/lib/index.ts';
import { OriginRole } from '../src/origin/control.ts';

type Json = Record<string, any>;
const rid = () => hex(randomBytes(16));
const ok = (r: Json, result: string) => { assert.equal(r['ok'], true, JSON.stringify(r)); assert.equal(r['result'], result); validateControlResponse(r); };
const fails = (r: Json, result: string) => { assert.equal(r['ok'], false, JSON.stringify(r)); assert.equal(r['result'], result); validateControlResponse(r); };

const spki = 'MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAyxrta2qV9bHOATpM_KsluUsuZKIwNOQlCn6rQ8DfOowSmTrxKxEZCNS0cb7DHUtsmtnN2pBhKi7pA1I-beWiJNawLwnlw3TQz-Adj1KcUAp4ovZ5CPpoK1orQwyB6vGvcte155T8mKMTknaHl1fORTtSbvm_bOuZl5uEI7kPRGGiKvN6qwz1cz91l6vkTTHHMttooYHGy75gfYwOUuBlX9mZbcWE7KC-h6-814ozfRex26noKLvYHikTFxROf_ifVWGXCbCWy7nqR0zq0mTCBz_kl0DAHwDhCRBgZpg9IeX4PwhuLoI8h5zUPO9wDSo1Kpur1hLQPK0C2xNLfiJaXwIDAQAB';
function rig() {
  const manifest = makeManifest({ run_id: rid(), run_start_ms: Date.now(), token_key_spki_b64url: spki, snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40) });
  const role = new OriginRole({ listen: { host: '127.0.0.1', port: 0 }, drainMs: 400 });
  let digest: string | null = null;
  const send = (command: string, payload: object = {}, over: object = {}) => role.handle({ version: 1, request_id: rid(), command, run_id: manifest.run_id,
    config_digest: digest, target_incarnation: role.incarnation, payload, ...over }) as Promise<Json>;
  return {
    manifest, role, send,
    async toEnabled() {
      ok(await send('PREPARE_RUN', { manifest, proposed_config_digest: configurationDigest(manifest), role: 'origin', role_config: {} }, { config_digest: null }), 'PREPARED');
      digest = configurationDigest(manifest);
      ok(await send('CHECK_READY'), 'READY'); ok(await send('ENABLE'), 'ENABLED');
    },
    get: (path: string, headers: Record<string, string | string[]> = {}, method = 'GET') => new Promise<{ status: number; body: Buffer }>((resolve, reject) => {
      const r = request({ host: '127.0.0.1', port: role.address!.port, path, method, headers, agent: false }, (res) => {
        const c: Buffer[] = []; res.on('data', (d: Buffer) => c.push(d)); res.on('end', () => resolve({ status: res.statusCode!, body: Buffer.concat(c) }));
      });
      r.on('error', reject); r.end();
    }),
    counters: async () => ((await send('REPORT'))['data'] as Json)['counters'] as Json,
  };
}

test('received is counted before generation validation; mismatch and served are independent', async () => {
  const r = rig(); await r.toEnabled();
  const good = { 'X-TokenForge-Run': r.manifest.run_id };
  assert.deepEqual(await r.counters(), { protected_requests_received: 0, generation_mismatches: 0, resources_served: 0 });
  const served = await r.get('/resource', good);
  assert.equal(served.status, 200); assert.equal(served.body.length, 1024);
  assert.deepEqual(await r.counters(), { protected_requests_received: 1, generation_mismatches: 0, resources_served: 1 });
  // Wrong generation: received +1, mismatch +1, served unchanged.
  assert.equal((await r.get('/resource', { 'X-TokenForge-Run': 'f'.repeat(32) })).status, 421);
  assert.deepEqual(await r.counters(), { protected_requests_received: 2, generation_mismatches: 1, resources_served: 1 });
  // Missing header, duplicate header (even if one matches) and non-GET all count as arrivals; none is served.
  assert.equal((await r.get('/resource')).status, 421);
  assert.equal((await r.get('/resource', { 'X-TokenForge-Run': [r.manifest.run_id, r.manifest.run_id] })).status, 421);
  assert.equal((await r.get('/resource', good, 'POST')).status, 405);
  assert.deepEqual(await r.counters(), { protected_requests_received: 5, generation_mismatches: 3, resources_served: 1 });
  // Other paths are not the protected route and are not counted.
  assert.equal((await r.get('/other', good)).status, 404);
  assert.equal((await r.get('/resource/extra', good)).status, 404);
  assert.deepEqual(await r.counters(), { protected_requests_received: 5, generation_mismatches: 3, resources_served: 1 });
  await r.send('FENCE', { reason: 'test-cleanup' });
});

test('malformed requests that never parse are not counted as arrivals', async () => {
  const r = rig(); await r.toEnabled();
  await new Promise<void>((resolve) => { const s = connect(r.role.address!.port, '127.0.0.1', () => s.write('GET /resource HTTP/1.1\r\nBad Header\r\n\r\n')); s.on('close', () => resolve()); s.on('data', () => undefined); setTimeout(() => { s.destroy(); resolve(); }, 300); });
  assert.equal((await r.counters())['protected_requests_received'], 0);
  await r.send('FENCE', { reason: 'test-cleanup' });
});

test('nothing listens before ENABLE; FENCE closes the listener and the final counts stay available', async () => {
  const r = rig();
  assert.equal(r.role.address, null);
  ok(await r.send('PREPARE_RUN', { manifest: r.manifest, proposed_config_digest: configurationDigest(r.manifest), role: 'origin', role_config: {} }, { config_digest: null }), 'PREPARED');
  assert.equal(r.role.address, null, 'PREPARED does not listen');
  await r.role.handle({ version: 1, request_id: rid(), command: 'STATUS', run_id: null, config_digest: null, target_incarnation: null, payload: {} });
  const digest = configurationDigest(r.manifest);
  ok(await r.send('CHECK_READY', {}, { config_digest: digest }), 'READY');
  assert.equal(r.role.address, null, 'READY does not listen');
  ok(await r.send('ENABLE', {}, { config_digest: digest }), 'ENABLED');
  const port = r.role.address!.port;
  await r.get('/resource', { 'X-TokenForge-Run': r.manifest.run_id });
  ok(await r.send('FENCE', { reason: 'operator-stop' }, { config_digest: digest }), 'FENCED');
  await assert.rejects(new Promise((_res, rej) => { const s = connect(port, '127.0.0.1'); s.on('error', rej); s.on('connect', () => { s.destroy(); _res(null); }); }));
  const rep = (await r.send('REPORT', {}, { config_digest: digest }))['data'] as Json;
  assert.deepEqual(rep['counters'], { protected_requests_received: 1, generation_mismatches: 0, resources_served: 1 });
  assert.equal(rep['origin_counts_available'], true);
  fails(await r.send('ENABLE', {}, { config_digest: digest }), 'ILLEGAL_STATE');
  fails(await r.send('PREPARE_RUN', { manifest: r.manifest, proposed_config_digest: digest, role: 'origin', role_config: {} }, { config_digest: null }), 'ILLEGAL_STATE');
});

test('envelope and role checks', async () => {
  const r = rig();
  fails(await r.send('PREPARE_RUN', { manifest: r.manifest, proposed_config_digest: configurationDigest(r.manifest), role: 'gateway', role_config: {} }, { config_digest: null }), 'BAD_MESSAGE');
  fails(await r.send('HEARTBEAT', { seq: 1 }, { config_digest: '0'.repeat(64) }), 'ILLEGAL_STATE');
  fails(await r.send('PROVISION_CLIENT', { batch_id: 'a'.repeat(32), batch_index: 0, expected_total: 1, final_batch: true, items: ['A'.repeat(43)] }, { config_digest: '0'.repeat(64) }), 'ILLEGAL_STATE');
  fails(await r.send('CHECK_READY', {}, { target_incarnation: rid(), config_digest: '0'.repeat(64) }), 'WRONG_INCARNATION');
  fails(await r.send('CHECK_READY', {}, { config_digest: '0'.repeat(64) }), 'WRONG_RUN');
});
