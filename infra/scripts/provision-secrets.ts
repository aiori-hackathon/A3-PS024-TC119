// Generates the lab's infrastructure credentials into the git-ignored .runtime/secrets/ (plan section 8):
//   issuer/tls.crt tls.key      issuer TLS identity (issuer.lab.test)
//   client/ca.crt               lab CA certificate, mounted into clients so they can pin trust
//   gateway/tls.crt tls.key     gateway TLS identity (origin.lab.test); NOT mounted anywhere, the controller passes it over stdin
//   redis/redis-acl.conf        controller account for Redis (mounted into Redis only)
//   controller/redis-password   same password for the host-side controller
// The CA private key is never written (it lives only in this process), tokens/vouchers/signing keys are not
// handled here, and existing material is never overwritten. Usage: node infra/scripts/provision-secrets.ts
import { chmodSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createPki } from '../../src/services/lab/src/pki.ts';
import { PROTOCOL } from '../../src/contracts/lib/index.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '.runtime', 'secrets');
if (existsSync(root)) {
  console.error(`Refusing to overwrite existing secrets at ${root}. Remove the directory deliberately to rotate everything.`);
  process.exit(1);
}
const pki = createPki('TokenForge Lab CA', 7);
const issuer = pki.leaf(PROTOCOL.issuer_name);
const gateway = pki.leaf(PROTOCOL.origin_name);
const password = randomBytes(32).toString('base64url');

// Directories are owner-only. File modes stay readable (0644) so a container UID that differs from the host user can
// still read its mounted secret; protection comes from the 0700 parent and from mounting each file into one role only.
const write = (rel: string, data: string) => {
  const path = join(root, rel);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, data, { mode: 0o644, flag: 'wx' });
  try { chmodSync(path, 0o644); } catch { /* not meaningful on every host filesystem */ }
};
write('issuer/tls.crt', issuer.cert);
write('issuer/tls.key', issuer.key);
write('client/ca.crt', pki.caPem);
write('gateway/tls.crt', gateway.cert);
write('gateway/tls.key', gateway.key);
write('redis/redis-acl.conf', `user controller on >${password} ~* &* +@all\n`);
write('controller/redis-password', password);
for (const dir of ['', 'issuer', 'client', 'gateway', 'redis', 'controller']) { try { chmodSync(join(root, dir), 0o700); } catch { /* host-dependent */ } }
console.log(`Provisioned lab secrets under ${root} (7-day certificates; CA key discarded). Nothing was printed.`);
