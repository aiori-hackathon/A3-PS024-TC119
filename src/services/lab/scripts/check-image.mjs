// Lab-owned G0 image check. Usage: node scripts/check-image.mjs [image]
import { spawnSync } from 'node:child_process';
const image = process.argv[2] ?? 'tokenforge-lab-g0:local';
function docker(args, input) {
  const r = spawnSync('docker', args, { input, encoding: 'utf8', shell: false, timeout: 120000, maxBuffer: 1024 * 1024 });
  if (r.error || r.status !== 0) throw Error('Docker lab G0 check failed: ' + (r.stderr || r.error?.message || 'nonzero exit'));
  return r.stdout.trim();
}
const config = JSON.parse(docker(['image', 'inspect', image]))[0].Config;
if (config.User !== 'node' || config.ExposedPorts) throw Error('Image user/port boundary failed');
const restrictions = ['--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '128m', '--pids-limit', '64'];
const smoke = JSON.parse(docker(['run', ...restrictions, image]));
if (smoke.component !== 'lab-contract-bootstrap' || smoke.node_major !== 24 || smoke.contract_version !== 'TF-PS024-1.0.0' ||
    smoke.verified !== true || smoke.request_bytes !== 259 || smoke.token_bytes !== 354) throw Error('Lab bootstrap smoke mismatch');
const script = `
import { readdirSync, readFileSync, existsSync } from 'node:fs';
const app = readdirSync('/app');
if (app.some((p) => !['dist', 'node_modules'].includes(p))) throw Error('Unexpected app payload');
if (JSON.stringify(readdirSync('/app/dist').sort()) !== JSON.stringify(['bootstrap.mjs', 'client.mjs', 'control-helper.mjs', 'issuer.mjs', 'origin.mjs'])) throw Error('Unexpected build payload');
for (const p of ['typescript', 'esbuild', 'ajv']) if (existsSync('/app/node_modules/' + p)) throw Error('Dev tool in runtime: ' + p);
if (JSON.parse(readFileSync('/app/node_modules/sjcl/package.json', 'utf8')).version !== '1.0.9') throw Error('sjcl override missing');
for (const f of readdirSync('/app/dist')) {
  const bundle = readFileSync('/app/dist/' + f, 'utf8');
  if (/services[\\\\/]gateway|policy-golden|rfc9578-public/.test(bundle)) throw Error('Gateway/fixture material in bundle: ' + f);
}
for (const p of ['/src', '/test', '/fixtures', '/build']) if (existsSync(p)) throw Error('Source tree in runtime: ' + p);
console.log(JSON.stringify({ platform: process.platform, node: process.versions.node, runtime_payload: 'production-only' }));
`;
console.log(docker(['run', ...restrictions, '-i', image, 'node', '--input-type=module', '-'], script));
console.log('PASS: lab image is non-root, no-network, read-only; minimal payload; fresh Linux blind issuance and verification.');
