// Dedicated recovery-test client only. Stdout is a PRIVATE captured pipe to its parent harness.
// Quarantined old credentials never become a normal inventory/control response or public test output.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { connect } from 'node:net';
import { createServer } from 'node:http';
import { request as httpsRequest, type RequestOptions } from 'node:https';
import { setTimeout as delay } from 'node:timers/promises';
import { Redis } from 'ioredis';
import { publicVerif, TokenChallenge } from '@cloudflare/privacypass-ts';
import { PROTOCOL, configurationDigest, makeManifest, encodeBase64Url, decodeBase64Url, redemptionContext, validateControlResponse } from '../../../contracts/lib/index.ts';
import { REPLAY_SCRIPTS } from '../src/replay-scripts.ts';
import type { GatewayTls } from '../src/https-gateway.ts';

async function main(): Promise<void> {
  const input = JSON.parse(readFileSync(0, 'utf8')) as {
    phase: 'old' | 'fresh'; tls: GatewayTls; password: string;
    previous?: { run_id: string; token_key_id: string; spent: string; unused: string };
  };
  if (!['old', 'fresh'].includes(input.phase)) throw Error();
  const admin = new Redis({ host: '127.0.0.1', port: 6379, protocol: 2, lazyConnect: true,
    enableReadyCheck: false, disableClientInfo: true, retryStrategy: () => null });
  admin.on('error', () => {}); await admin.connect();
  let child: ReturnType<typeof spawn> | undefined, childExit: Promise<void> | undefined;
  let owner: ReturnType<typeof connect> | undefined;
  let heartbeatTimer: ReturnType<typeof setInterval> | undefined, heartbeat: Promise<void> | null = null, heartbeatFailed = false;
  let received = 0, served = 0, mismatches = 0;
  const origin = createServer((req, res) => {
    if (req.url !== '/resource') { res.writeHead(404).end(); return; }
    received++;
    if (req.headers['x-tokenforge-run'] !== manifest.run_id) { mismatches++; res.writeHead(409).end(); return; }
    served++; res.end('fresh-generation resource');
  });
  const mode = publicVerif.BlindRSAMode.PSS;
  const keys = await publicVerif.Issuer.generateKey(mode, { modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) });
  const spki = await publicVerif.getPublicKeyBytes(keys.publicKey);
  const time = await admin.time(), now = Number(time[0]) * 1000 + Math.floor(Number(time[1]) / 1000);
  const manifest = makeManifest({ run_id: randomBytes(16).toString('hex'), run_start_ms: now - 300000,
    token_key_spki_b64url: encodeBase64Url(spki), snapshot_script_sha1: REPLAY_SCRIPTS.snapshot.sha1, claim_script_sha1: REPLAY_SCRIPTS.claim.sha1 });
  const digest = configurationDigest(manifest);
  let incarnation: string | null = null;
  try {
    // A genuinely fresh Redis process, not FLUSHDB/reloaded old state.
    assert.equal(await admin.dbsize(), 0);
    await admin.acl('SETUSER', 'gateway', 'reset', 'on', `>${input.password}`, '~pp:policy', '~pp:clock', '~pp:spent:*', '-@all',
      '+auth', '+type', '+pttl', '+hlen', '+hmget', '+time', '+get', '+pexpiretime', '+hset', '+set', '+evalsha', '+script|exists');
    for (const script of Object.values(REPLAY_SCRIPTS)) assert.equal(await admin.script('LOAD', script.source), script.sha1);
    await admin.hset('pp:policy', { schema_version: '1', run_id: manifest.run_id, token_type: '2', token_key_id: manifest.token_key_id,
      config_digest: digest, run_start_ms: String(manifest.run_start_ms), epoch_ms: '600000', guard_ms: '30000' });
    await admin.hset('pp:clock', { run_id: manifest.run_id, last_now_ms: String(manifest.run_start_ms), highest_epoch: '0', closed: '0' });
    origin.listen(8080, '127.0.0.1'); await once(origin, 'listening');
    child = spawn(process.execPath, ['dist/serve.mjs'], { stdio: ['pipe', 'ignore', 'ignore'] });
    childExit = new Promise<void>(resolve => child!.once('exit', () => resolve()));
    child.stdin!.end(JSON.stringify({ tls: input.tls, redis: { username: 'gateway', password: input.password }, listen_host: '127.0.0.1' }));
    for (let i = 0; i < 150; i++) {
      try { const link = connect(PROTOCOL.control_socket); link.on('error', () => {}); await once(link, 'connect'); owner = link; break; }
      catch { if (child.exitCode !== null || child.signalCode !== null) throw Error(); await delay(20); }
    }
    if (!owner) throw Error();
    let carry = '';
    const pending = new Map<string, (reply: Record<string, unknown>) => void>();
    owner.on('data', data => {
      carry += data.toString(); let newline: number;
      while ((newline = carry.indexOf('\n')) >= 0) {
        const reply = JSON.parse(carry.slice(0, newline)) as Record<string, unknown>; carry = carry.slice(newline + 1);
        validateControlResponse(reply); pending.get(reply['request_id'] as string)?.(reply); pending.delete(reply['request_id'] as string);
      }
    });
    async function call(command: string, payload: unknown = {}) {
      const request_id = randomBytes(16).toString('hex');
      const request = { version: 1, request_id, command, run_id: command === 'STATUS' ? null : manifest.run_id,
        config_digest: command === 'STATUS' || command === 'PREPARE_RUN' ? null : digest, target_incarnation: incarnation, payload };
      return new Promise<Record<string, unknown>>((resolve, reject) => {
        const timer = setTimeout(() => { pending.delete(request_id); reject(Error('recovery-control-timeout')); }, 8000);
        pending.set(request_id, reply => { clearTimeout(timer); resolve(reply); }); owner!.write(JSON.stringify(request) + '\n');
      });
    }
    const status = await call('STATUS'); incarnation = status['incarnation'] as string; assert.equal(status['state'], 'FENCED');
    assert.equal((await call('PREPARE_RUN', { manifest, proposed_config_digest: digest, role: 'gateway', role_config: {} }))['result'], 'PREPARED');
    assert.equal((await call('CHECK_READY'))['result'], 'READY'); assert.equal((await call('ENABLE'))['result'], 'ENABLED');
    let sequence = 0;
    heartbeatTimer = setInterval(() => {
      if (heartbeat || pending.size) return;
      heartbeat = call('HEARTBEAT', { seq: ++sequence }).then(reply => {
        if (reply['result'] !== 'HEARTBEAT_ACK') heartbeatFailed = true;
      }, () => { heartbeatFailed = true; }).finally(() => { heartbeat = null; });
    }, 1000);
    function get(wire: Uint8Array) {
      return new Promise<{ status: number; label: string }>((resolve, reject) => {
        const options: RequestOptions & { ALPNProtocols: string[] } = { host: '127.0.0.1', port: 443, servername: manifest.origin_name, ca: input.tls.cert,
          minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'], agent: false, path: '/resource',
          headers: { Host: manifest.origin_name, Authorization: `PrivateToken token="${encodeBase64Url(wire)}"` } };
        const req = httpsRequest(options, res => {
          let body = ''; res.on('data', b => { body += b.toString(); }); res.once('error', reject);
          res.once('end', () => { clearTimeout(timer); let label = ''; try { label = (JSON.parse(body) as { error: string }).error; } catch { /* resource bytes */ }
            resolve({ status: res.statusCode!, label }); });
        });
        const timer = setTimeout(() => req.destroy(), 5000); req.once('error', () => { clearTimeout(timer); reject(Error('recovery-https-failed')); }); req.end();
      });
    }
    async function issue() {
      const client = new publicVerif.Client(mode), challenge = new TokenChallenge(2, manifest.issuer_name, redemptionContext(manifest, 0), [manifest.origin_name]);
      const request = await client.createTokenRequest(challenge, spki);
      return (await client.finalize(await new publicVerif.Issuer(mode, manifest.issuer_name, keys.privateKey, keys.publicKey).issue(request))).serialize();
    }
    let quarantine: { spent: string; unused: string } | null = null;
    if (input.phase === 'old') {
      const spent = await issue(), unused = await issue();
      assert.equal((await get(spent)).status, 200); assert.equal((await get(spent)).status, 401);
      assert.equal(received, 1); assert.equal(served, 1); assert.equal(mismatches, 0);
      quarantine = { spent: encodeBase64Url(spent), unused: encodeBase64Url(unused) };
    } else {
      const previous = input.previous; if (!previous) throw Error();
      assert.notEqual(manifest.run_id, previous.run_id); assert.notEqual(manifest.token_key_id, previous.token_key_id);
      for (const token of [previous.spent, previous.unused]) {
        const reply = await get(decodeBase64Url(token, 354)); assert.equal(reply.status, 401); assert.equal(reply.label, 'token-key-unknown');
      }
      assert.equal(received, 0); assert.equal((await admin.keys('pp:spent:*')).length, 0);
      const fresh = await issue(); assert.equal((await get(fresh)).status, 200); assert.equal((await get(fresh)).status, 401);
      for (const token of [previous.spent, previous.unused]) assert.equal((await get(decodeBase64Url(token, 354))).status, 401);
      assert.equal(received, 1); assert.equal(served, 1); assert.equal(mismatches, 0); assert.equal((await admin.keys('pp:spent:*')).length, 1);
    }
    clearInterval(heartbeatTimer); heartbeatTimer = undefined; if (heartbeat) await heartbeat;
    assert.equal(heartbeatFailed, false);
    const fenced = await call('FENCE', { reason: 'test-cleanup' }); assert.equal(fenced['result'], 'FENCED');
    assert.equal(readFileSync(`/proc/${child.pid}/task/${child.pid}/children`, 'utf8').trim(), '');
    assert.equal((await call('ENABLE'))['ok'], false);
    // Stop the independently counted origin before the private result is released.
    origin.closeAllConnections(); await new Promise<void>(resolve => origin.close(() => resolve()));
    child.kill('SIGTERM'); await childExit; child = undefined; owner.destroy(); owner = undefined; admin.disconnect(false);
    process.stdout.write(JSON.stringify({ phase: input.phase, manifest, gateway_incarnation: incarnation, received, served, mismatches, quarantine }));
  } finally {
    if (heartbeatTimer) clearInterval(heartbeatTimer);
    owner?.destroy(); if (child) { child.kill('SIGKILL'); await childExit; }
    origin.closeAllConnections(); if (origin.listening) await new Promise<void>(resolve => origin.close(() => resolve()));
    admin.disconnect(false);
  }
}
try { await main(); }
catch { process.stderr.write('recovery-phase-failed\n'); process.exitCode = 1; }
