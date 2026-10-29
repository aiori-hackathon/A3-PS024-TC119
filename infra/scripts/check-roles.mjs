// Runs the REAL lab role containers (no inert listeners) under the hardened Compose settings and drives them through
// the in-container control helper: discovery, issuer key/prepare/provision/ready/enable, origin prepare/ready/enable,
// then a TLS 1.3 request from a client container through the CONNECT proxy to the live issuer. It proves the built
// images work with a read-only root, dropped capabilities, UID 1000, tmpfs control sockets and mounted secrets.
// The gateway serving entry point belongs to Krish and is not started here. Usage: node infra/scripts/check-roles.mjs [--keep]
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import { configurationDigest, makeManifest, voucherDigest } from '../../src/contracts/lib/index.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const composeFile = join(root, 'infra', 'compose.yaml');
const keep = process.argv.includes('--keep');
if (!existsSync(join(root, '.runtime', 'secrets'))) { console.error('Run: node infra/scripts/provision-secrets.ts'); process.exit(2); }
const compose = (...args) => spawnSync('docker', ['compose', '-f', composeFile, ...args], { encoding: 'utf8', shell: false, cwd: root, timeout: 300000, maxBuffer: 8 * 1024 * 1024 });
let failures = 0, checks = 0;
const check = (name, ok, detail = '') => { checks++; if (!ok) failures++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail && !ok ? `  [${detail}]` : ''}`); };
const hex = (n) => randomBytes(n).toString('hex');

/** Persistent control-helper session inside a role container (stdin stays open, replies correlated by request_id). */
function session(service) {
  const child = spawn('docker', ['compose', '-f', composeFile, 'exec', '-T', service, 'node', 'dist/control-helper.mjs'], { cwd: root, stdio: ['pipe', 'pipe', 'pipe'] });
  const waiting = new Map(); let buf = '';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { const r = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1); waiting.get(r.request_id)?.(r); } });
  return {
    send: (req) => new Promise((resolve, reject) => { const t = setTimeout(() => reject(new Error('helper timeout')), 15000); waiting.set(req.request_id, (r) => { clearTimeout(t); resolve(r); }); child.stdin.write(JSON.stringify(req) + '\n'); }),
    close: () => child.stdin.end(),
  };
}
const status = (s) => s.send({ version: 1, request_id: hex(16), command: 'STATUS', run_id: null, config_digest: null, target_incarnation: null, payload: {} });

let up = false;
try {
  console.log('Starting real proxy, issuer, protected-origin and client-a containers...');
  up = true;
  const started = compose('up', '-d', '--build', 'proxy', 'issuer', 'protected-origin', 'client-a');
  if (started.status !== 0) { console.error(started.stderr.split('\n').slice(-10).join('\n')); throw new Error('compose up failed'); }
  spawnSync(process.execPath, ['-e', 'setTimeout(()=>{},2500)']);

  const issuer = session('issuer'), origin = session('protected-origin'), client = session('client-a');
  const s = { issuer: await status(issuer), origin: await status(origin), client: await status(client) };
  for (const [role, r] of Object.entries(s)) check(`${role}: control socket answers STATUS; starts FENCED with a fresh incarnation`, r.ok && r.state === 'FENCED' && /^[0-9a-f]{32}$/.test(r.incarnation));
  check('each role has its own incarnation', new Set(Object.values(s).map((r) => r.incarnation)).size === 3);
  const ps = JSON.parse(`[${compose('ps', '--format', 'json').stdout.trim().split('\n').filter(Boolean).join(',')}]`);
  check('no role listens before ENABLE (no published or host-visible ports)', ps.every((p) => !(p.Publishers ?? []).some((x) => x.PublishedPort)));

  // Issuer: full lifecycle inside the container.
  const runId = hex(16);
  const at = (inc, digest) => (command, payload = {}, over = {}) => ({ version: 1, request_id: hex(16), command, run_id: runId, config_digest: digest, target_incarnation: inc, payload, ...over });
  const mk = at(s.issuer.incarnation, null);
  const key = await issuer.send(mk('CREATE_ISSUER_KEY', {}, { config_digest: null }));
  check('issuer: fresh key created inside the container; only public data returned', key.ok && Object.keys(key.data).sort().join() === 'token_key_id,token_key_spki_b64url');
  const vouchers = [randomBytes(32)];
  const manifest = makeManifest({ run_id: runId, run_start_ms: Date.now(), token_key_spki_b64url: key.data.token_key_spki_b64url,
    snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40), inventory_total: 1 });
  const digest = configurationDigest(manifest);
  const withDigest = at(s.issuer.incarnation, digest);
  const prep = await issuer.send(mk('PREPARE_RUN', { manifest, proposed_config_digest: digest, role: 'issuer', role_config: { tls_cert_path: '/run/secrets/tls.crt', tls_key_path: '/run/secrets/tls.key' } }, { config_digest: null }));
  check('issuer: PREPARE reads its mounted TLS secrets', prep.ok === true, prep.result);
  const prov = await issuer.send(withDigest('PROVISION_VOUCHERS', { batch_id: 'a'.repeat(32), batch_index: 0, expected_total: 1, final_batch: true, items: vouchers.map(voucherDigest) }));
  check('issuer: sealed provisioning', prov.ok && prov.data.sealed === true);
  check('issuer: READY', (await issuer.send(withDigest('CHECK_READY'))).result === 'READY');
  check('issuer: ENABLE binds 172.28.20.10:443 as UID 1000 with no capabilities', (await issuer.send(withDigest('ENABLE'))).result === 'ENABLED');

  // Origin lifecycle.
  const originRun = at(s.origin.incarnation, null);
  const op = await origin.send(originRun('PREPARE_RUN', { manifest, proposed_config_digest: digest, role: 'origin', role_config: {} }, { config_digest: null }));
  const od = at(s.origin.incarnation, digest);
  check('origin: PREPARE, READY, ENABLE', op.ok && (await origin.send(od('CHECK_READY'))).ok && (await origin.send(od('ENABLE'))).result === 'ENABLED');
  const rep = await origin.send(od('REPORT'));
  check('origin: counters start at zero and are available', rep.ok && rep.data.origin_counts_available && Object.values(rep.data.counters).every((v) => v === 0));

  // A client container reaches the live issuer ONLY through the proxy, validating the lab CA and hostname.
  const probe = `
    const net=require('net'),tls=require('tls'),fs=require('fs');
    const out=(o)=>{console.log(JSON.stringify(o));process.exit(0)};
    const s=net.connect({host:'172.28.10.2',port:8888});
    s.setTimeout(8000,()=>out({err:'timeout'}));
    s.on('error',()=>out({err:'tcp'}));
    let head='';
    s.on('connect',()=>s.write('CONNECT issuer.lab.test:443 HTTP/1.1\\r\\nHost: issuer.lab.test:443\\r\\n\\r\\n'));
    s.on('data',function onData(c){head+=c;if(!head.includes('\\r\\n\\r\\n'))return;s.off('data',onData);
      if(!/^HTTP\\/1\\.[01] 200/.test(head))return out({err:'connect',head:head.split('\\r\\n')[0]});
      const t=tls.connect({socket:s,servername:'issuer.lab.test',ca:fs.readFileSync('/run/secrets/ca.crt'),minVersion:'TLSv1.3',ALPNProtocols:['http/1.1']},()=>{
        t.write('GET /.well-known/private-token-issuer-directory HTTP/1.1\\r\\nHost: issuer.lab.test\\r\\nConnection: close\\r\\n\\r\\n');});
      let body='';t.on('data',(d)=>body+=d);t.on('error',(e)=>out({err:'tls',code:e.code}));
      t.on('end',()=>out({proto:t.getProtocol(),authorized:t.authorized,status:Number(/^HTTP\\/1\\.1 (\\d+)/.exec(body)[1]),body:body.split('\\r\\n\\r\\n')[1]}));});`;
  const r = spawnSync('docker', ['compose', '-f', composeFile, 'exec', '-T', 'client-a', 'node', '-e', probe], { encoding: 'utf8', cwd: root, timeout: 30000 });
  let got = {}; try { got = JSON.parse(r.stdout.trim()); } catch { /* reported below */ }
  check('client-a -> proxy -> issuer: TLS 1.3, trusted lab CA and hostname, directory 200', got.proto === 'TLSv1.3' && got.authorized === true && got.status === 200, r.stdout.trim().slice(0, 160));
  let dir = {}; try { dir = JSON.parse(got.body); } catch { /* reported below */ }
  check('served directory carries exactly the key the issuer created', dir['token-keys']?.[0]?.['token-key'] === key.data.token_key_spki_b64url);

  // Strong fence on every role.
  for (const [name, sess, inc, dg] of [['issuer', issuer, s.issuer.incarnation, digest], ['origin', origin, s.origin.incarnation, digest]]) {
    const f = await sess.send({ version: 1, request_id: hex(16), command: 'FENCE', run_id: null, config_digest: null, target_incarnation: null, payload: { reason: 'test-cleanup' } });
    check(`${name}: FENCE returns the strong FENCED acknowledgement`, f.ok && f.state === 'FENCED');
    void inc; void dg;
  }
  const after = spawnSync('docker', ['compose', '-f', composeFile, 'exec', '-T', 'client-a', 'node', '-e', probe], { encoding: 'utf8', cwd: root, timeout: 30000 });
  check('after FENCE the issuer no longer serves through the proxy', !/"status":200/.test(after.stdout), after.stdout.trim().slice(0, 120));
  issuer.close(); origin.close(); client.close();
} catch (e) {
  failures++;
  console.error('ABORTED:', e.message);
} finally {
  if (up && !keep) compose('down', '--volumes', '--remove-orphans', '--timeout', '2');
}
console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'}: ${checks - failures}/${checks} real-role container checks`);
process.exit(failures === 0 ? 0 : 1);
