// Test-only stand-ins: a CONNECT proxy that maps lab hostnames to local ports, and a minimal gateway that issues the
// 401 challenge and checks tokens. The stub gateway is NOT the real gateway; it exists to exercise the client.
import { createServer as netServer, connect, type Server as NetServer, type Socket } from 'node:net';
import { createServer as httpsServer, type Server } from 'node:https';
import { PROTOCOL, challengeBytes, encodeBase64Url, hex, sha256, type Manifest } from '../../../../contracts/lib/index.ts';
import { Token, TOKEN_TYPES } from '@cloudflare/privacypass-ts';
import { verifyTokenSignature } from '../../src/protocol.ts';
import { listen } from './https.ts';

export type StubProxy = { server: NetServer; port: number; connects: string[]; open: () => number; peak: () => number; setMode: (m: 'ok' | 'refuse' | 'extra') => void };
/** `routes` maps "host:port" to a local port. Anything else is refused with 403, like the real allowlist. */
export async function startProxy(routes: Record<string, number>): Promise<StubProxy> {
  const connects: string[] = [];
  const sockets = new Set<Socket>();
  let mode: 'ok' | 'refuse' | 'extra' = 'ok';
  let tunnels = 0, peak = 0;
  const server = netServer((client) => {
    sockets.add(client); client.on('close', () => sockets.delete(client)); client.on('error', () => client.destroy());
    let head = Buffer.alloc(0);
    const onData = (d: Buffer) => {
      head = Buffer.concat([head, d]);
      const end = head.indexOf('\r\n\r\n');
      if (end < 0) return;
      client.off('data', onData);
      const first = head.subarray(0, head.indexOf('\r\n')).toString('latin1');
      const m = /^CONNECT ([^ ]+) HTTP\/1\.1$/.exec(first);
      const target = m?.[1];
      connects.push(target ?? first);
      const port = target ? routes[target] : undefined;
      if (mode === 'refuse' || port === undefined) { client.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'); return; }
      const upstream = connect({ host: '127.0.0.1', port }, () => {
        tunnels += 1; peak = Math.max(peak, tunnels); client.on('close', () => { tunnels -= 1; });
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n' + (mode === 'extra' ? 'junk' : ''));
        client.pipe(upstream); upstream.pipe(client);
      });
      sockets.add(upstream); upstream.on('close', () => sockets.delete(upstream));
      upstream.on('error', () => client.destroy()); client.on('close', () => upstream.destroy());
    };
    client.on('data', onData);
  });
  server.on('close', () => { for (const s of sockets) s.destroy(); });
  const port = await listen(server as unknown as Server);
  return { server, port, connects, open: () => sockets.size, peak: () => peak, setMode: (v) => { mode = v; } };
}

export type StubGateway = {
  server: Server; port: number; spent: Set<string>; requests: { auth: string | undefined }[];
  /** Overrides the challenge header value for the next 401s. */
  header: { override: string | null }; delayMs: { value: number }; active: { max: number; now: number };
};
export async function startGateway(m: Manifest, epoch: () => number, tls: { key: string; cert: string }): Promise<StubGateway> {
  const spent = new Set<string>();
  const requests: { auth: string | undefined }[] = [];
  const header = { override: null as string | null };
  const delayMs = { value: 0 };
  const active = { max: 0, now: 0 };
  const server = httpsServer({ ...tls, minVersion: 'TLSv1.3' }, async (req, res) => {
    active.now += 1; active.max = Math.max(active.max, active.now);
    res.on('close', () => { active.now -= 1; });
    if (delayMs.value) await new Promise((r) => setTimeout(r, delayMs.value));
    const auth = req.headers.authorization;
    requests.push({ auth });
    const challenge = () => header.override ?? `PrivateToken challenge="${encodeBase64Url(challengeBytes(m, epoch()))}", token-key="${m.token_key_spki_b64url}"`;
    const reject = () => { res.writeHead(401, { 'WWW-Authenticate': challenge(), 'Cache-Control': 'no-store', 'Content-Length': '0' }); res.end(); };
    if (!auth) return reject();
    const match = /^PrivateToken token="([A-Za-z0-9_-]+)"$/.exec(auth);
    if (!match) return reject();
    try {
      const wire = Uint8Array.from(Buffer.from(match[1]!, 'base64url'));
      const token = Token.deserialize(TOKEN_TYPES.BLIND_RSA, wire);
      const ok = hex(token.authInput.challengeDigest) === hex(sha256(challengeBytes(m, epoch())))
        && await verifyTokenSignature(Buffer.from(m.token_key_spki_b64url, 'base64url'), wire);
      if (!ok || spent.has(match[1]!)) return reject();
      spent.add(match[1]!);
      res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': '2', 'Cache-Control': 'no-store' }); res.end('ok');
    } catch { reject(); }
  });
  return { server, port: await listen(server), spent, requests, header, delayMs, active };
}
void PROTOCOL;
