import { X509Certificate, createPrivateKey } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

export type ReadinessCheck = { check: string; ok: boolean; action?: string };
export function supportedVersion(value:string,minimum:readonly number[]):boolean {
  const match=/^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(value.trim());
  if(!match)return false;
  const parts=match.slice(1).map(Number);
  for(let i=0;i<3;i++){if(parts[i]!>minimum[i]!)return true;if(parts[i]!<minimum[i]!)return false;}
  return true;
}
/** Fixed diagnostics only: never return exception text, file contents or credentials. */
export function localReadiness(root: string, now = Date.now()): ReadinessCheck[] {
  const checks: ReadinessCheck[] = [];
  const check = (name: string, action: string, test: () => boolean) => {
    let ok = false; try { ok = test(); } catch { /* fixed diagnostic below */ }
    checks.push({ check: name, ok, ...(ok ? {} : { action }) });
  };
  check('pinned-node-patch', 'Use Node from .node-version', () => process.versions.node === readFileSync(join(root, '.node-version'), 'utf8').trim());
  check('openssl-test-tool', 'Install OpenSSL 3 or newer for the component TLS tests (Git for Windows is supported)', () => {
    const fallback='C:\\Program Files\\Git\\usr\\bin\\openssl.exe';
    const executable=process.platform==='win32'&&existsSync(fallback)?fallback:'openssl';
    const r=spawnSync(executable,['version'],{encoding:'utf8',timeout:5000,shell:false,windowsHide:true});
    return r.status===0 && Number(/^OpenSSL (\d+)\./.exec(r.stdout)?.[1])>=3;
  });
  for (const service of ['gateway', 'lab']) check(`${service}-locked-dependencies`, `Run npm ci --ignore-scripts --prefix src/services/${service}`, () => {
    const dir = join(root, 'src', 'services', service);
    const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
    const lock = JSON.parse(readFileSync(join(dir, 'package-lock.json'), 'utf8'));
    return Object.entries({ ...pkg.dependencies, ...pkg.devDependencies }).every(([name, version]) => {
      const installed = JSON.parse(readFileSync(join(dir, 'node_modules', name, 'package.json'), 'utf8'));
      return installed.version === version && lock.packages[`node_modules/${name}`]?.version === version;
    });
  });
  const secrets = join(root, '.runtime', 'secrets');
  const cert = (p: string) => new X509Certificate(readFileSync(join(secrets, p)));
  check('tls-validity-trust-and-key-pairs', 'Fence the lab, move expired .runtime/secrets aside, then run node infra/scripts/provision-secrets.ts', () => {
    const ca = cert('client/ca.crt');
    if (!ca.ca || now < Date.parse(ca.validFrom) || now >= Date.parse(ca.validTo)) return false;
    return [['issuer', 'issuer.lab.test'], ['gateway', 'origin.lab.test']].every(([role, host]) => {
      const leaf = cert(`${role}/tls.crt`);
      return now >= Date.parse(leaf.validFrom) && now < Date.parse(leaf.validTo) && !!leaf.checkHost(host!, { wildcards: false })
        && leaf.verify(ca.publicKey) && leaf.checkPrivateKey(createPrivateKey(readFileSync(join(secrets, role!, 'tls.key'))));
    });
  });
  check('redis-credential-and-acl', 'Provision matching controller and Redis credentials', () => {
    const password = readFileSync(join(secrets, 'controller', 'redis-password'), 'utf8');
    return /^[A-Za-z0-9_-]{43}$/.test(password)
      && readFileSync(join(secrets, 'redis', 'redis-acl.conf'), 'utf8') === `user controller on >${password} ~* &* +@all\n`;
  });
  if (process.platform !== 'win32') check('secret-directory-permissions', 'Set .runtime/secrets and each role directory to mode 0700', () =>
    ['', 'issuer', 'gateway', 'client', 'controller', 'redis'].every(p => (statSync(join(secrets, p)).mode & 0o077) === 0));
  if (process.platform !== 'win32') check('secret-file-permissions', 'Remove group/other write permissions from secret files; keep role directories owner-only', () =>
    ['issuer/tls.crt','issuer/tls.key','gateway/tls.crt','gateway/tls.key','client/ca.crt','controller/redis-password','redis/redis-acl.conf'].every(p=>{const s=statSync(join(secrets,p));return s.isFile()&&(s.mode&0o022)===0;}));
  return checks;
}
