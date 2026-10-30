import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, unlink, rmdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { GatewayTls } from '../src/https-gateway.ts';

/** Ephemeral test credentials only; no key output, checked-in PEM or environment secret. */
export async function createTestTls(): Promise<GatewayTls> {
  const directory = await mkdtemp(join(tmpdir(), 'tokenforge-tls-'));
  const keyFile = join(directory, 'key.pem'), certFile = join(directory, 'cert.pem');
  const openssl = process.platform === 'win32' && existsSync('C:\\Program Files\\Git\\usr\\bin\\openssl.exe')
    ? 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe' : 'openssl';
  try {
    await promisify(execFile)(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '1', '-nodes',
      '-subj', '/CN=origin.lab.test', '-addext', 'subjectAltName=DNS:origin.lab.test',
      '-keyout', keyFile, '-out', certFile], { timeout: 30000, windowsHide: true });
    return { key: await readFile(keyFile, 'utf8'), cert: await readFile(certFile, 'utf8') };
  } catch { throw new Error('test-tls-generation-failed'); }
  finally {
    // Explicit known files, no recursive deletion or shell-built paths.
    await Promise.all([unlink(keyFile).catch(() => {}), unlink(certFile).catch(() => {})]);
    await rmdir(directory);
  }
}
