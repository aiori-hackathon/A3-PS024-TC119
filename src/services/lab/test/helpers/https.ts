import { request } from 'node:https';
import { connect } from 'node:tls';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:https';

export const listen = (server: Server): Promise<number> =>
  new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)));

export type Reply = { status: number; headers: Record<string, string | string[] | undefined>; body: Buffer };
export function https(port: number, ca: string, opts: { method?: string; path: string; headers?: Record<string, string | string[]>; body?: Uint8Array }): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, servername: 'issuer.lab.test', ca, method: opts.method ?? 'GET', path: opts.path,
      headers: opts.headers, minVersion: 'TLSv1.3', agent: false }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    req.end(opts.body ? Buffer.from(opts.body) : undefined);
  });
}
/** Writes raw bytes over TLS (for malformed-framing tests) and returns whatever the server sends before closing. */
export function rawTls(port: number, ca: string, bytes: string | Buffer, settleMs = 300): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = connect({ host: '127.0.0.1', port, servername: 'issuer.lab.test', ca, minVersion: 'TLSv1.3' }, () => s.write(bytes));
    let out = '';
    s.on('data', (d) => { out += d.toString('latin1'); });
    s.on('error', reject);
    s.on('close', () => resolve(out));
    setTimeout(() => s.destroy(), settleMs);
  });
}
