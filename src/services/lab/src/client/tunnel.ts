// HTTP/1.1 over TLS 1.3 through an HTTP CONNECT proxy, with a pinned lab CA and expected hostname.
// The proxy sees only the destination host:port, never the TLS contents. No rejectUnauthorized=false, no redirects.
import { connect as tcpConnect, type Socket } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { Agent } from 'node:https';
import type { Duplex } from 'node:stream';

export type TunnelTarget = { host: string; port: number };
export type TunnelOptions = {
  proxy: { host: string; port: number }; caPem: string; allowedHosts: readonly string[]; maxSockets: number; connectTimeoutMs?: number;
};
const MAX_CONNECT_HEAD = 8192;
const CRLF2 = Buffer.from([13, 10, 13, 10]);

function openTunnel(o: TunnelOptions, target: TunnelTarget, timeoutMs: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = tcpConnect({ host: o.proxy.host, port: o.proxy.port });
    let head = Buffer.alloc(0);
    const timer = setTimeout(() => fail('tunnel-timeout'), timeoutMs);
    const fail = (e: string) => { clearTimeout(timer); socket.destroy(); reject(new Error(e)); };
    socket.once('error', () => fail('tunnel-error'));
    socket.once('connect', () => {
      const authority = `${target.host}:${target.port}`;
      socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
    });
    const onData = (chunk: Buffer) => {
      head = Buffer.concat([head, chunk]);
      const end = head.indexOf(CRLF2);
      if (end < 0) { if (head.length > MAX_CONNECT_HEAD) fail('tunnel-head'); return; }
      socket.off('data', onData); clearTimeout(timer);
      if (!/^HTTP\/1\.[01] 200[ \r]/.test(head.subarray(0, end + 2).toString('latin1'))) return fail('tunnel-refused');
      if (head.length !== end + 4) return fail('tunnel-extra-bytes'); // nothing may precede the TLS handshake
      resolve(socket);
    };
    socket.on('data', onData);
  });
}

type ConnOptions = { host?: string | null; hostname?: string | null; port?: number | string | null; servername?: string };

/** Agent whose sockets are CONNECT tunnels + verified TLS. maxSockets bounds concurrent sockets per destination. */
export class TunnelAgent extends Agent {
  readonly #o: TunnelOptions;
  constructor(o: TunnelOptions) {
    super({ keepAlive: true, maxSockets: o.maxSockets, maxFreeSockets: o.maxSockets, keepAliveMsecs: 1000, timeout: 10000 });
    this.#o = o;
  }
  // Node supports an asynchronous createConnection(options, callback); the base typings predate that form.
  override createConnection(options: ConnOptions, cb: (err: Error | null, s?: Duplex) => void): undefined {
    const host = String(options.servername ?? options.hostname ?? options.host ?? '');
    const port = Number(options.port ?? 443);
    if (!this.#o.allowedHosts.includes(host) || port !== 443) { cb(new Error('destination-not-allowed')); return undefined; }
    const timeout = this.#o.connectTimeoutMs ?? 2000;
    openTunnel(this.#o, { host, port }, timeout).then((raw) => {
      const tls = tlsConnect({ socket: raw, servername: host, ca: this.#o.caPem, minVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'] });
      const timer = setTimeout(() => tls.destroy(new Error('tls-timeout')), timeout);
      tls.once('secureConnect', () => { clearTimeout(timer); cb(null, tls); });
      tls.once('error', (e) => { clearTimeout(timer); cb(e); });
    }, (e: Error) => cb(e));
    return undefined;
  }
}
