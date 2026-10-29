// Brings the authoritative Compose stack up with inert TCP listeners where the serving entry points are not yet
// available, then proves the boundaries from the plan's section 8 with real traffic from inside the containers:
// reachability matrix, DNS isolation, CONNECT misuse, container hardening, secret mounts and Redis posture.
// The listeners only accept and close; they stand in for processes and prove network paths, not application behavior.
// Usage: node infra/scripts/check-network.mjs [--keep]      (needs Docker with Linux containers; run provision-secrets first)
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const composeFile = join(root, 'infra', 'compose.yaml');
const keep = process.argv.includes('--keep');
// Self-test: deliberately breaks isolation (client-a joins the Redis network). The run MUST then fail.
const leak = process.argv.includes('--mutate-leak');
if (!existsSync(join(root, '.runtime', 'secrets'))) { console.error('Run: node infra/scripts/provision-secrets.ts'); process.exit(2); }

const run = (cmd, args, opts = {}) => spawnSync(cmd, args, { encoding: 'utf8', shell: false, cwd: root, timeout: 180000, maxBuffer: 8 * 1024 * 1024, ...opts });
const dir = mkdtempSync(join(tmpdir(), 'ps024-netcheck-'));
writeFileSync(join(dir, 'listen.mjs'), `
import { createServer } from 'node:net';
const [host, port] = process.argv.slice(2);
createServer((s) => { s.on('error', () => {}); s.end(); }).listen(Number(port), host);
`);
const dirUnix = dir.replaceAll('\\', '/');
// Test-only override: inert listeners in place of the role processes that need a controller to open a port.
writeFileSync(join(dir, 'override.yaml'), `
services:
  issuer:
    command: ["node", "/probe/listen.mjs", "172.28.20.10", "443"]
    volumes: ["${dirUnix}/listen.mjs:/probe/listen.mjs:ro"]
  gateway:
    command: ["node", "/probe/listen.mjs", "172.28.30.10", "443"]
    volumes: ["${dirUnix}/listen.mjs:/probe/listen.mjs:ro"]
  protected-origin:
    command: ["node", "/probe/listen.mjs", "172.28.50.10", "8080"]
    volumes: ["${dirUnix}/listen.mjs:/probe/listen.mjs:ro"]
${leak ? `  client-a:
    networks:
      gateway_replay: { ipv4_address: 172.28.40.99 }
` : ''}`);
const compose = (...args) => run('docker', ['compose', '-f', composeFile, '-f', join(dir, 'override.yaml'), ...args]);

let failures = 0, checks = 0;
const check = (name, ok, detail = '') => { checks++; if (!ok) failures++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail && !ok ? `  [${detail}]` : ''}`); };

// --- probes -------------------------------------------------------------------------------------------------------
const NODE_SERVICES = new Set(['issuer', 'gateway', 'protected-origin', 'client-a', 'client-b', 'client-c', 'client-d', 'client-e']);
const inside = (service, argv, env = {}) => {
  const envArgs = Object.entries(env).flatMap(([k, v]) => ['-e', `${k}=${v}`]);
  return compose('exec', '-T', ...envArgs, service, ...argv);
};
/** true when a TCP connection is accepted within 2 s. */
function tcpOpen(from, host, port) {
  if (NODE_SERVICES.has(from)) {
    const script = `const s=require('net').connect({host:${JSON.stringify(host)},port:${port}});const t=setTimeout(()=>{console.log('NO');process.exit(0)},2000);s.on('connect',()=>{console.log('OPEN');process.exit(0)});s.on('error',()=>{console.log('NO');process.exit(0)});`;
    return inside(from, ['node', '-e', script]).stdout.trim() === 'OPEN';
  }
  return inside(from, ['nc', '-z', '-w', '2', host, String(port)]).status === 0;
}
function resolves(from, name) {
  if (NODE_SERVICES.has(from)) {
    const script = `require('dns').lookup(${JSON.stringify(name)},(e,a)=>{console.log(e?'NO':'YES '+a);process.exit(0)});setTimeout(()=>{console.log('NO');process.exit(0)},3000)`;
    return inside(from, ['node', '-e', script]).stdout.trim().startsWith('YES');
  }
  return inside(from, ['getent', 'hosts', name]).status === 0;
}
/** Returns the proxy's reply status line code for a raw request sent from a client container. */
function viaProxy(request) {
  const script = `const s=require('net').connect({host:'172.28.10.2',port:8888});let d='';const done=()=>{const m=/^HTTP\\/1\\.[01] (\\d+)/.exec(d);console.log(m?m[1]:'NONE');process.exit(0)};s.setTimeout(4000,done);s.on('connect',()=>s.write(${JSON.stringify(request)}));s.on('data',(c)=>{d+=c;if(d.includes('\\r\\n'))done()});s.on('error',done);s.on('close',done);`;
  return inside('client-a', ['node', '-e', script]).stdout.trim();
}

let up = false;
try {
  console.log('Building and starting the stack (inert listeners for issuer, gateway and origin)...');
  const started = compose('up', '-d', '--build', '--remove-orphans');
  up = true;
  if (started.status !== 0) { console.error(started.stderr.split('\n').slice(-12).join('\n')); throw new Error('compose up failed'); }
  // Wait for every service to be running.
  const services = ['proxy', 'issuer', 'gateway', 'redis', 'protected-origin', 'client-a', 'client-b', 'client-c', 'client-d', 'client-e'];
  for (let i = 0; i < 40; i++) {
    const ps = JSON.parse(`[${compose('ps', '--format', 'json').stdout.trim().split('\n').filter(Boolean).join(',')}]`);
    if (services.every((s) => ps.find((p) => p.Service === s)?.State === 'running')) break;
    run(process.execPath, ['-e', 'setTimeout(()=>{},1000)']);
    if (i === 39) throw new Error('services did not reach running: ' + ps.map((p) => `${p.Service}:${p.State}`).join(' '));
  }
  run(process.execPath, ['-e', 'setTimeout(()=>{},1500)']);
  check('every service is running (roles start fenced, nothing restarts)', true);

  // --- reachability matrix ----------------------------------------------------------------------------------------
  const ISSUER = ['172.28.20.10', 443], GATEWAY = ['172.28.30.10', 443], REDIS = ['172.28.40.10', 6379], ORIGIN = ['172.28.50.10', 8080];
  const PROXY_CLIENT = ['172.28.10.2', 8888];
  const matrix = [
    // [from, target label, [host, port], expected open]
    ['client-a', 'proxy', PROXY_CLIENT, true],
    ['client-a', 'issuer (direct)', ISSUER, false], ['client-a', 'gateway (direct)', GATEWAY, false],
    ['client-a', 'redis', REDIS, false], ['client-a', 'protected origin', ORIGIN, false],
    ['client-e', 'proxy', PROXY_CLIENT, true], ['client-e', 'redis', REDIS, false], ['client-e', 'protected origin', ORIGIN, false],
    ['proxy', 'issuer', ISSUER, true], ['proxy', 'gateway', GATEWAY, true],
    ['proxy', 'redis', REDIS, false], ['proxy', 'protected origin', ORIGIN, false],
    ['issuer', 'gateway', GATEWAY, false], ['issuer', 'redis', REDIS, false], ['issuer', 'protected origin', ORIGIN, false], ['issuer', 'proxy', PROXY_CLIENT, false],
    ['gateway', 'redis', REDIS, true], ['gateway', 'protected origin', ORIGIN, true],
    ['gateway', 'issuer', ISSUER, false], ['gateway', 'proxy', PROXY_CLIENT, false],
    ['redis', 'gateway', GATEWAY, false], ['redis', 'protected origin', ORIGIN, false], ['redis', 'issuer', ISSUER, false],
    ['protected-origin', 'gateway', GATEWAY, false], ['protected-origin', 'redis', REDIS, false], ['protected-origin', 'issuer', ISSUER, false],
  ];
  for (const [from, label, [host, port], expected] of matrix) {
    const open = tcpOpen(from, host, port);
    check(`${from} -> ${label} ${expected ? 'reachable' : 'blocked'}`, open === expected, open ? 'connected' : 'no connection');
  }
  // Clients cannot reach the outside world (internal bridges): a public address must be unreachable.
  check('client-a -> public internet blocked', !tcpOpen('client-a', '1.1.1.1', 443));
  check('gateway -> public internet blocked', !tcpOpen('gateway', '1.1.1.1', 443));

  // --- DNS isolation ----------------------------------------------------------------------------------------------
  for (const name of ['issuer.lab.test', 'origin.lab.test', 'redis', 'protected-origin']) check(`client-a cannot resolve ${name}`, !resolves('client-a', name));
  check('proxy resolves issuer.lab.test', resolves('proxy', 'issuer.lab.test'));
  check('proxy resolves origin.lab.test', resolves('proxy', 'origin.lab.test'));
  check('gateway resolves redis and protected-origin', resolves('gateway', 'redis') && resolves('gateway', 'protected-origin'));
  check('issuer cannot resolve redis or protected-origin', !resolves('issuer', 'redis') && !resolves('issuer', 'protected-origin'));

  // --- CONNECT misuse ---------------------------------------------------------------------------------------------
  const connect = (hostport) => viaProxy(`CONNECT ${hostport} HTTP/1.1\r\nHost: ${hostport}\r\n\r\n`);
  for (const ok of ['issuer.lab.test:443', 'origin.lab.test:443']) check(`CONNECT ${ok} allowed`, connect(ok) === '200', connect(ok));
  const denied = ['issuer.lab.test:80', 'issuer.lab.test:8443', 'issuer.lab.test:22', 'example.com:443', '172.28.20.10:443', '172.28.30.10:443',
    '172.28.40.10:6379', '172.28.50.10:8080', 'redis:6379', 'protected-origin:8080', 'localhost:443', '127.0.0.1:443',
    'issuer.lab.test.evil.example:443', 'evilissuer.lab.test:443', 'ISSUER.LAB.TEST.:443', 'issuer.lab.test:0443'];
  for (const target of denied) { const code = connect(target); check(`CONNECT ${target} refused`, /^(400|403|404|405|407|50\d)$/.test(code), code); }
  for (const req of ['GET http://issuer.lab.test/ HTTP/1.1\r\nHost: issuer.lab.test\r\n\r\n', 'GET http://origin.lab.test:443/resource HTTP/1.1\r\nHost: origin.lab.test\r\n\r\n',
    'GET http://protected-origin:8080/resource HTTP/1.1\r\nHost: protected-origin\r\n\r\n']) {
    const code = viaProxy(req); check(`plain proxying refused: ${req.split(' ')[1]}`, /^(400|403|404|405|407|50\d)$/.test(code), code);
  }

  // --- container hardening, mounts, networks ----------------------------------------------------------------------
  const names = compose('ps', '-q').stdout.trim().split(/\s+/).filter(Boolean);
  const inspect = JSON.parse(run('docker', ['inspect', ...names]).stdout);
  const byService = Object.fromEntries(inspect.map((c) => [c.Config.Labels['com.docker.compose.service'], c]));
  const expectSecrets = { issuer: ['tls.crt', 'tls.key'], 'client-a': ['ca.crt'], 'client-b': ['ca.crt'], 'client-c': ['ca.crt'], 'client-d': ['ca.crt'], 'client-e': ['ca.crt'], redis: ['redis-acl.conf'], gateway: [], proxy: [], 'protected-origin': [] };
  const expectNets = { proxy: ['client_proxy', 'proxy_gateway', 'proxy_issuer'], issuer: ['proxy_issuer'], gateway: ['gateway_origin', 'gateway_replay', 'proxy_gateway'],
    redis: ['gateway_replay'], 'protected-origin': ['gateway_origin'], 'client-a': ['client_proxy'], 'client-b': ['client_proxy'], 'client-c': ['client_proxy'], 'client-d': ['client_proxy'], 'client-e': ['client_proxy'] };
  for (const [service, c] of Object.entries(byService)) {
    const h = c.HostConfig;
    const mounts = c.Mounts.map((m) => m.Destination);
    check(`${service}: read-only root, all caps dropped, no-new-privileges, not privileged`,
      h.ReadonlyRootfs === true && JSON.stringify(h.CapDrop) === '["ALL"]' && h.SecurityOpt?.includes('no-new-privileges:true') && h.Privileged === false);
    check(`${service}: no restart, no Docker-managed log data, no host network, no PID/IPC sharing`,
      (h.RestartPolicy.Name === 'no' || h.RestartPolicy.Name === '') && h.LogConfig.Type === 'none' && h.NetworkMode !== 'host' && !h.PidMode && !h.IpcMode?.startsWith('container:'));
    check(`${service}: no published ports and no host port bindings`, Object.keys(h.PortBindings ?? {}).length === 0);
    check(`${service}: runs as a non-root user`, !!c.Config.User && !c.Config.User.startsWith('0'));
    check(`${service}: no Docker socket or host path mounts`, !c.Mounts.some((m) => /docker\.sock/.test(m.Source) || /docker\.sock/.test(m.Destination)) && !mounts.includes('/'));
    const secretFiles = mounts.filter((d) => d.startsWith('/run/secrets/')).map((d) => d.slice('/run/secrets/'.length)).sort();
    check(`${service}: mounts exactly its own secrets (${secretFiles.join(',') || 'none'})`, JSON.stringify(secretFiles) === JSON.stringify([...(expectSecrets[service] ?? [])].sort()));
    const nets = Object.keys(c.NetworkSettings.Networks).map((n) => n.replace(/^tokenforge_/, '')).sort();
    check(`${service}: member of exactly ${expectNets[service].join(', ')}`, JSON.stringify(nets) === JSON.stringify(expectNets[service]), nets.join(','));
    check(`${service}: environment carries no credentials`, !c.Config.Env.some((e) => /(PASSWORD|SECRET|PRIVATE|TOKEN|CREDENTIAL)/i.test(e.split('=')[0])));
  }
  const nets = JSON.parse(run('docker', ['network', 'inspect', ...['client_proxy', 'proxy_issuer', 'proxy_gateway', 'gateway_replay', 'gateway_origin'].map((n) => `tokenforge_${n}`)]).stdout);
  check('all five bridges are internal, IPv6-off, with the planned subnets', nets.length === 5 && nets.every((n) => n.Internal === true && n.EnableIPv6 === false) &&
    JSON.stringify(nets.map((n) => n.IPAM.Config[0].Subnet).sort()) === JSON.stringify(['172.28.10.0/24', '172.28.20.0/24', '172.28.30.0/24', '172.28.40.0/24', '172.28.50.0/24']));
  for (const svc of ['proxy', 'gateway']) {
    const fwd = inside(svc, ['cat', '/proc/sys/net/ipv4/ip_forward']).stdout.trim();
    check(`${svc}: IPv4 forwarding disabled between its networks`, fwd === '0', fwd);
  }
  for (const svc of ['proxy', 'gateway', 'issuer', 'redis']) {
    const v6 = inside(svc, ['cat', '/proc/sys/net/ipv6/conf/all/disable_ipv6']).stdout.trim();
    check(`${svc}: IPv6 disabled`, v6 === '1', v6);
  }
  check('control socket directory is a private tmpfs (issuer)', /tmpfs.*\/run\/ps024.*mode=700/.test(inside('issuer', ['cat', '/proc/mounts']).stdout));

  // --- Redis posture ----------------------------------------------------------------------------------------------
  const anon = inside('gateway', ['node', '-e', `const s=require('net').connect({host:'172.28.40.10',port:6379});let d='';s.on('connect',()=>s.write('*1\\r\\n$4\\r\\nPING\\r\\n'));s.on('data',(c)=>{d+=c;console.log(d.trim());process.exit(0)});setTimeout(()=>{console.log('TIMEOUT');process.exit(0)},2000)`]).stdout.trim();
  check('Redis refuses unauthenticated clients (default user off)', /^-(NOAUTH|WRONGPASS|ERR)/.test(anon), anon);
  const password = readFileSync(join(root, '.runtime', 'secrets', 'controller', 'redis-password'), 'utf8');
  const cli = (...argv) => inside('redis', ['redis-cli', '-s', '/run/redis/redis.sock', '--user', 'controller', ...argv], { REDISCLI_AUTH: password });
  check('controller account works over the private local socket', cli('PING').stdout.trim() === 'PONG');
  const wantConfig = { 'slowlog-max-len': '0', 'slowlog-log-slower-than': '-1', 'acllog-max-len': '0', 'latency-monitor-threshold': '0', 'notify-keyspace-events': '', appendonly: 'no', save: '', bind: '172.28.40.10' };
  for (const [key, want] of Object.entries(wantConfig)) {
    const out = cli('CONFIG', 'GET', key).stdout.split('\n').map((l) => l.trim());
    check(`Redis ${key} = ${want === '' ? '(empty)' : want}`, out[0] === key && (out[1] ?? '') === want, out.join('|'));
  }
  check('Redis has no default-user access even locally', /NOAUTH|WRONGPASS|ERR/.test(inside('redis', ['redis-cli', '-s', '/run/redis/redis.sock', 'PING']).stdout));
} catch (e) {
  failures++;
  console.error('ABORTED:', e.message);
} finally {
  if (up && !keep) {
    compose('down', '--volumes', '--remove-orphans', '--timeout', '2');
    const leftover = run('docker', ['ps', '-aq', '--filter', 'label=com.docker.compose.project=tokenforge']).stdout.trim();
    check('teardown leaves no containers', leftover === '', leftover);
  }
}
console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'}: ${checks - failures}/${checks} network and hardening checks`);
process.exit(failures === 0 ? 0 : 1);
