// Run after `npm run build`. Confirms the lab bundles are self-contained and that the built issuer process can be
// driven end to end through the built control helper, using only files, a private socket and stdin.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, writeFileSync, mkdtempSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { connect } from 'node:net';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  PROTOCOL, makeManifest, configurationDigest, encodeBase64Url, voucherDigest, hex,
} from '../../../contracts/lib/index.ts';
import { LabIssuance, challengeFor, verifyTokenSignature } from '../src/protocol.ts';
import { createPki } from './helpers/pki.ts';
import { https, listen } from './helpers/https.ts';
import { createServer } from 'node:https';

const dist = new URL('../dist/', import.meta.url);
const bundle = (name: string) => fileURLToPath(new URL(name, dist));

test('dist holds only the four role bundles and no gateway/fixture/test source', () => {
  assert.deepEqual(readdirSync(dist).sort(), ['bootstrap.mjs', 'client.mjs', 'control-helper.mjs', 'issuer.mjs']);
  for (const name of readdirSync(dist)) {
    const text = readFileSync(new URL(name, dist), 'utf8');
    assert.match(text, /PS024-context-v1|control_socket/, `${name}: shared contract is bundled`);
    assert.doesNotMatch(text, /services[\\/]gateway/i);
    assert.doesNotMatch(text, /policy-golden|rfc9578-public/);
  }
});

test('bootstrap bundle runs standalone: real issuance and public verification', () => {
  const r = spawnSync(process.execPath, [bundle('bootstrap.mjs')], { encoding: 'utf8', timeout: 60000 });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.deepEqual([out.component, out.contract_version, out.request_bytes, out.token_bytes, out.verified],
    ['lab-contract-bootstrap', 'TF-PS024-1.0.0', 259, 354, true]);
  assert.equal(out.node_major, 24);
});

const sockPath = () => process.platform === 'win32'
  ? ['', '', '.', 'pipe', `ps024-proc-${randomBytes(6).toString('hex')}`].join(String.fromCharCode(92))
  : join(mkdtempSync(join(tmpdir(), 'ps024-')), 'control.sock');
const freePort = async () => { const s = createServer(); const p = await listen(s); await new Promise((r) => s.close(r)); return p; };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitForSocket(path: string): Promise<void> {
  for (let i = 0; i < 100; i++) {
    const ok = await new Promise<boolean>((resolve) => { const s = connect(path); s.once('connect', () => { s.destroy(); resolve(true); }); s.once('error', () => resolve(false)); });
    if (ok) return;
    await sleep(50);
  }
  throw new Error('role did not open its control socket');
}
function helper(env: NodeJS.ProcessEnv) {
  const child = spawn(process.execPath, [bundle('control-helper.mjs')], { env, stdio: ['pipe', 'pipe', 'pipe'] });
  const waiting = new Map<string, (r: any) => void>();
  let buf = '', err = '';
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', (d: string) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { const r = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1); waiting.get(r.request_id)?.(r); } });
  child.stderr.on('data', (d: string) => { err += d; });
  const exited = new Promise<number | null>((r) => child.on('close', (code) => r(code)));
  return {
    child, exited, stderr: () => err, stdout: () => buf,
    send: (req: Record<string, unknown>) => new Promise<any>((resolve) => { waiting.set(req['request_id'] as string, resolve); child.stdin.write(JSON.stringify(req) + '\n'); }),
  };
}

test('built issuer process: full lifecycle through the built control helper, real issuance, strong fence', { timeout: 60000 }, async () => {
  const pki = createPki();
  const leaf = pki.leaf(PROTOCOL.issuer_name);
  const secrets = mkdtempSync(join(tmpdir(), 'ps024-secrets-'));
  writeFileSync(join(secrets, 'tls.crt'), leaf.cert); writeFileSync(join(secrets, 'tls.key'), leaf.key);
  const control = sockPath(); const port = await freePort();
  const env = { ...process.env, PS024_CONTROL_SOCKET: control, PS024_SECRETS_DIR: secrets, PS024_BIND_ADDRESS: '127.0.0.1', PS024_LISTEN_PORT: String(port) };
  const role: ChildProcess = spawn(process.execPath, [bundle('issuer.mjs')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let roleOutput = ''; role.stdout!.on('data', (d) => { roleOutput += d; }); role.stderr!.on('data', (d) => { roleOutput += d; });
  let h: ReturnType<typeof helper> | undefined;
  try {
    await waitForSocket(control);
    h = helper(env); // the helper dials immediately, so it starts only once the socket exists
    const send = h.send;
    const id = () => hex(randomBytes(16));
    const envelope = (command: string, payload: object, over: object) => ({ version: 1, request_id: id(), command, payload, ...over });
    const status = await send(envelope('STATUS', {}, { run_id: null, config_digest: null, target_incarnation: null }));
    assert.equal(status.state, 'FENCED');
    const inc = status.incarnation as string; const runId = id();
    const at = (command: string, payload: object = {}, over: object = {}) => send(envelope(command, payload, { run_id: runId, config_digest: digest, target_incarnation: inc, ...over }));
    let digest: string | null = null;
    const key = await at('CREATE_ISSUER_KEY', {}, { config_digest: null });
    assert.equal(key.ok, true, JSON.stringify(key));
    const manifest = makeManifest({ run_id: runId, run_start_ms: Date.now() - 1000, token_key_spki_b64url: key.data.token_key_spki_b64url,
      snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40), inventory_total: 2 });
    const prep = await at('PREPARE_RUN', { manifest, proposed_config_digest: configurationDigest(manifest), role: 'issuer',
      role_config: { tls_cert_path: '/run/secrets/tls.crt', tls_key_path: '/run/secrets/tls.key' } }, { config_digest: null });
    assert.equal(prep.ok, true, JSON.stringify(prep));
    digest = configurationDigest(manifest);
    const vouchers = [randomBytes(32), randomBytes(32)];
    assert.equal((await at('PROVISION_VOUCHERS', { batch_id: 'b'.repeat(32), batch_index: 0, expected_total: 2, final_batch: true, items: vouchers.map(voucherDigest) })).data.sealed, true);
    assert.equal((await at('CHECK_READY')).result, 'READY');
    assert.equal((await at('ENABLE')).result, 'ENABLED');
    const spki = Buffer.from(key.data.token_key_spki_b64url, 'base64url');
    const issuance = await LabIssuance.begin(challengeFor(manifest, 0), spki);
    const res = await https(port, pki.caPem, { method: 'POST', path: '/issue', body: issuance.requestWire,
      headers: { 'Content-Type': 'application/private-token-request', 'X-Lab-Voucher': encodeBase64Url(vouchers[0]!, false) } });
    assert.equal(res.status, 200);
    assert.equal(await verifyTokenSignature(spki, await issuance.finalize(res.body)), true);
    assert.equal((await at('HEARTBEAT', { seq: 1 })).result, 'HEARTBEAT_ACK');
    assert.equal((await at('FENCE', { reason: 'operator-stop' })).result, 'FENCED');
    await assert.rejects(https(port, pki.caPem, { path: '/.well-known/private-token-issuer-directory' }));
    // Nothing secret was written to the process output streams.
    assert.equal(roleOutput, '');
    assert.doesNotMatch(h.stderr() + roleOutput, /PRIVATE KEY|X-Lab-Voucher/);
  } finally {
    h?.child.stdin.end(); role.kill();
  }
});

test('control helper fails closed with a fixed message on malformed input and never echoes it', async () => {
  const control = sockPath();
  const dummy = spawn(process.execPath, ['-e', `require('net').createServer(s=>s.on('data',()=>{})).listen(${JSON.stringify(control)})`], { stdio: 'ignore' });
  try {
    await waitForSocket(control);
    const h = helper({ ...process.env, PS024_CONTROL_SOCKET: control });
    h.child.stdin.write('{"version":1,"secret":"do-not-echo"}\n');
    assert.equal(await h.exited, 1);
    assert.equal(h.stderr(), 'control-helper-failed\n');
    assert.doesNotMatch(h.stdout() + h.stderr(), /do-not-echo/);
  } finally { dummy.kill(); }
});
