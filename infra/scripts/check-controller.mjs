// Drives the REAL controller (`lab run --no-gateway --dev-redis`) against the real Compose containers and proves the
// supervision properties that only real processes can show:
//   A. a live run stays enabled well past the 3 s lease (heartbeats work)
//   B. SIGKILL of the controller: no cleanup runs, yet the issuer closes itself when its lease lapses (controller loss)
//   C. the stale project lock is NOT treated as proof that anything stopped; a second controller is refused
//   D. `lab fence` stops every reachable role with strong acknowledgements
//   E. killing one role container makes the controller close the whole run through the barrier, discard the old Redis
//      container, and confirm it, exiting 0
// Out of scope: the gateway and the real replay-store bootstrap (not available yet), and any claim about throughput.
// Usage: node infra/scripts/check-controller.mjs
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const composeFile = join(root, 'infra', 'compose.yaml');
const cli = join(root, 'src', 'services', 'lab', 'src', 'controller', 'cli.ts');
const lockPath = join(root, '.runtime', 'project.lock');
const sh = (cmd, args, o = {}) => spawnSync(cmd, args, { encoding: 'utf8', cwd: root, shell: false, timeout: 600000, ...o });
const compose = (...a) => sh('docker', ['compose', '-f', composeFile, ...a]);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0, checks = 0;
const check = (name, ok, detail = '') => { checks++; if (!ok) failures++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail && !ok ? `  [${detail}]` : ''}`); };
const hex = () => randomBytes(16).toString('hex');

/** Starts the controller; resolves lines as they appear. */
function startController(extra = []) {
  const child = spawn(process.execPath, [cli, 'run', '--no-gateway', '--dev-redis', '--per-client', '2', ...extra], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
  const lines = []; let buf = ''; const waiters = [];
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 1); try { lines.push(JSON.parse(l)); } catch { /* ignore */ } for (const w of waiters.splice(0)) w(); } });
  child.stderr.resume();
  const exited = new Promise((r) => child.on('close', (code, sig) => r({ code, sig })));
  const waitFor = async (pred, ms) => { const end = Date.now() + ms; for (;;) { const hit = lines.find(pred); if (hit) return hit; if (Date.now() > end) return null; await new Promise((r) => { waiters.push(r); setTimeout(r, 250); }); } };
  return { child, lines, exited, waitFor };
}
/** One-shot STATUS of a role through a fresh helper session inside its container. */
function status(service) {
  const id = compose('ps', '-q', service).stdout.trim().split('\n')[0];
  if (!id) return null;
  const req = JSON.stringify({ version: 1, request_id: hex(), command: 'STATUS', run_id: null, config_digest: null, target_incarnation: null, payload: {} }) + '\n';
  const r = sh('docker', ['exec', '-i', id, 'node', 'dist/control-helper.mjs'], { input: req, timeout: 20000 });
  try { return JSON.parse(r.stdout.trim().split('\n')[0]); } catch { return null; }
}
const directoryStatus = () => {
  const probe = `const net=require('net'),tls=require('tls'),fs=require('fs');const out=(o)=>{console.log(JSON.stringify(o));process.exit(0)};const s=net.connect({host:'172.28.10.2',port:8888});s.setTimeout(6000,()=>out({s:0}));s.on('error',()=>out({s:0}));let h='';s.on('connect',()=>s.write('CONNECT issuer.lab.test:443 HTTP/1.1\\r\\nHost: issuer.lab.test:443\\r\\n\\r\\n'));s.on('data',function f(c){h+=c;if(!h.includes('\\r\\n\\r\\n'))return;s.off('data',f);if(!/^HTTP\\/1\\.[01] 200/.test(h))return out({s:0});const t=tls.connect({socket:s,servername:'issuer.lab.test',ca:fs.readFileSync('/run/secrets/ca.crt'),minVersion:'TLSv1.3'},()=>t.write('GET /.well-known/private-token-issuer-directory HTTP/1.1\\r\\nHost: issuer.lab.test\\r\\nConnection: close\\r\\n\\r\\n'));let b='';t.on('data',(d)=>b+=d);t.on('error',()=>out({s:0}));t.on('end',()=>out({s:Number(/^HTTP\\/1\\.1 (\\d+)/.exec(b)?.[1]??0)}));});`;
  const r = compose('exec', '-T', 'client-a', 'node', '-e', probe);
  try { return JSON.parse(r.stdout.trim()).s; } catch { return 0; }
};

try {
  rmSync(lockPath, { force: true });
  compose('down', '--volumes', '--remove-orphans', '--timeout', '2');

  // preflight
  const pre = sh(process.execPath, [cli, 'preflight']);
  check('lab preflight passes on a provisioned host', pre.status === 0, pre.stdout);

  // ---- A + B + C + D ------------------------------------------------------------------------------------------
  console.log('Starting controller run 1 (builds images on first use)...');
  const a = startController();
  const enabled = await a.waitFor((l) => l.event === 'enabled', 420000);
  check('controller builds and enables a run with 7 roles (issuer, origin, clients A-E)', enabled?.roles === 7, JSON.stringify(a.lines.slice(-2)));
  check('output carries ids only (no secrets in controller output)', a.lines.every((l) => Object.keys(l).every((k) => ['event', 'run_id', 'config_digest', 'roles', 'error', 'step', 'detail'].includes(k))));
  await sleep(6000); // two full lease periods
  const live = status('issuer');
  check('A. issuer is still ENABLED after 6 s, i.e. past two 3 s leases (heartbeats renew it)', live?.state === 'ENABLED' && live?.ok === true, JSON.stringify(live?.state));
  check('A. live issuer serves through the proxy over TLS 1.3 (directory 200)', directoryStatus() === 200);
  check('A. controller still supervising (no closed event)', !a.lines.some((l) => l.event === 'closed'));
  check('project lock exists while the controller runs', existsSync(lockPath));

  a.child.kill('SIGKILL'); // no cleanup code can run
  const dead = await a.exited;
  check('B. controller process killed abruptly (no graceful shutdown)', dead.code !== 0);
  await sleep(5500);
  const lapsed = status('issuer');
  check('B. issuer closed itself after the lease lapsed: FAULTED, lease-expired, run latched closed', lapsed?.state === 'FAULTED' && lapsed?.data?.fault === 'lease-expired' && lapsed?.data?.run_closed === true, JSON.stringify(lapsed?.data));
  check('B. nothing serves any more through the proxy', directoryStatus() !== 200);
  check('C. the stale project lock was left in place (not trusted, not removed)', existsSync(lockPath));
  const second = sh(process.execPath, [cli, 'run', '--no-gateway', '--dev-redis']);
  check('C. a second controller is refused while the lock exists', second.status === 3 && /project-lock-held/.test(second.stdout), second.stdout);
  const fenced = sh(process.execPath, [cli, 'fence']);
  const fenceLines = fenced.stdout.trim().split('\n').map((l) => JSON.parse(l));
  check('D. lab fence: strong FENCED from all 7 reachable roles', fenced.status === 0 && fenceLines.filter((l) => l.fenced === true).length === 7, fenced.stdout);
  check('D. issuer reports FENCED with the run still latched closed', (() => { const s = status('issuer'); return s?.state === 'FENCED' && s?.data?.run_closed === true; })());
  rmSync(lockPath, { force: true }); // operator decision, after the fence confirmed everything stopped

  // ---- E ------------------------------------------------------------------------------------------------------
  console.log('Starting controller run 2 on freshly recreated roles...');
  const b = startController();
  const enabled2 = await b.waitFor((l) => l.event === 'enabled', 420000);
  check('E. second run starts on recreated roles (fresh incarnations, never reusing a closed one)', enabled2?.roles === 7 && enabled2.run_id !== enabled?.run_id, JSON.stringify(b.lines.slice(-2)));
  const redisBefore = compose('ps', '-q', 'redis').stdout.trim();
  const victim = compose('ps', '-q', 'client-c').stdout.trim();
  sh('docker', ['kill', victim]);
  const closed = await b.waitFor((l) => l.event === 'closed', 60000);
  const end = await b.exited;
  check('E. killing one client container closes the whole run (process-exited)', closed?.reason === 'process-exited', JSON.stringify(closed));
  check('E. strong barrier confirmed and old Redis discarded; controller exits 0', closed?.reset_confirmed === true && end.code === 0, JSON.stringify(end));
  check('E. the old Redis container no longer exists', redisBefore !== '' && sh('docker', ['inspect', redisBefore]).status !== 0);
  const iss = status('issuer');
  check('E. issuer fenced and latched closed; origin counters settled and reported', iss?.state === 'FENCED' && iss?.data?.run_closed === true && closed?.origin_counts && closed.origin_counts.protected_requests_received === 0, JSON.stringify(closed?.origin_counts));
  check('project lock released by the controller on a clean close', !existsSync(lockPath));
} catch (e) {
  failures++;
  console.error('ABORTED:', e.message);
} finally {
  compose('down', '--volumes', '--remove-orphans', '--timeout', '2');
  rmSync(lockPath, { force: true });
}
console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'}: ${checks - failures}/${checks} controller checks`);
process.exit(failures === 0 ? 0 : 1);
