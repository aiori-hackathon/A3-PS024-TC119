// Issuer HTTPS transport: TLS 1.3 / HTTP/1.1, bounded headers/body/sockets/deadlines, strict framing.
// Semantics live in IssuanceService; this file only decides what is framing (400/405/413/431) and what is not.
import { createServer, type Server } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import { PROTOCOL } from '../../../../contracts/lib/index.ts';
import type { IssuanceService } from './issuance.ts';
import { DIRECTORY_PATH, DIRECTORY_TYPE, directoryBody } from './directory.ts';

export type IssuerTls = { key: string | Buffer; cert: string | Buffer };
const ISSUE_PATH = new URL(PROTOCOL.issuer_request_uri).pathname;
const MAX_BODY = PROTOCOL.issuer_limits.body_max_bytes;
const MAX_HEADERS = PROTOCOL.issuer_limits.headers_max_count;

function reply(res: ServerResponse, status: number, type: string, body: Uint8Array, extra: Record<string, string> = {}, close = false): void {
  res.writeHead(status, {
    'Content-Type': type, 'Content-Length': String(body.length), 'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff', ...(close ? { Connection: 'close' } : {}), ...extra,
  });
  res.end(body);
}
const json = (res: ServerResponse, status: number, error: string, extra: Record<string, string> = {}, close = false) =>
  reply(res, status, 'application/json', new TextEncoder().encode(JSON.stringify({ error })), extra, close);

function rawValues(req: IncomingMessage, name: string): string[] {
  const out: string[] = [];
  for (let i = 0; i + 1 < req.rawHeaders.length; i += 2) if (req.rawHeaders[i]!.toLowerCase() === name) out.push(req.rawHeaders[i + 1]!);
  return out;
}

export function createIssuerServer(service: IssuanceService, publicKeySpki: Uint8Array, tls: IssuerTls): Server {
  const limits = PROTOCOL.issuer_limits;
  const directory = directoryBody(publicKeySpki);
  const server = createServer({
    ...tls, minVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'], maxHeaderSize: limits.headers_max_bytes,
    // Node truncates silently at the limit, so allow one more and reject the excess ourselves.
    requestTimeout: limits.request_timeout_ms, headersTimeout: limits.tls_header_timeout_ms, keepAliveTimeout: 5000,
    // No client certificates, no session-ticket reuse across processes.
    requestCert: false,
  });
  server.maxHeadersCount = MAX_HEADERS + 1;
  server.maxConnections = limits.sockets;
  server.setTimeout(limits.request_timeout_ms);
  server.on('tlsClientError', (_e, socket) => socket.destroy());
  server.on('clientError', (err: NodeJS.ErrnoException, socket: Duplex) => {
    if (!socket.writable) { socket.destroy(); return; }
    const status = err.code === 'HPE_HEADER_OVERFLOW' ? '431 Request Header Fields Too Large' : '400 Bad Request';
    socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\nCache-Control: no-store\r\n\r\n`);
  });
  server.on('request', (req, res) => { void route(req, res).catch(() => { if (!res.headersSent) json(res, 500, 'issuance-failed', {}, true); else res.destroy(); }); });

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.rawHeaders.length / 2 > MAX_HEADERS) { req.resume(); return json(res, 431, 'headers-too-large', {}, true); }
    const url = req.url ?? '';
    if (url === DIRECTORY_PATH) {
      if (req.method !== 'GET') return json(res, 405, 'method-not-allowed', { Allow: 'GET' });
      return reply(res, 200, DIRECTORY_TYPE, directory);
    }
    if (url !== ISSUE_PATH) return json(res, 404, 'not-found');
    if (req.method !== 'POST') return json(res, 405, 'method-not-allowed', { Allow: 'POST' });
    // Controlled HTTP/1.1 client: exactly one decimal Content-Length, no Transfer-Encoding.
    const lengths = rawValues(req, 'content-length');
    if (rawValues(req, 'transfer-encoding').length > 0 || lengths.length !== 1 || !/^[0-9]{1,5}$/.test(lengths[0]!)) {
      req.resume(); return json(res, 400, 'bad-request', {}, true);
    }
    const declared = Number(lengths[0]);
    if (declared > MAX_BODY) { return json(res, 413, 'payload-too-large', {}, true); }
    const chunks: Buffer[] = []; let total = 0;
    for await (const chunk of req) {
      total += (chunk as Buffer).length;
      if (total > MAX_BODY) return json(res, 413, 'payload-too-large', {}, true);
      chunks.push(chunk as Buffer);
    }
    if (total !== declared) return json(res, 400, 'bad-request', {}, true);
    const types = rawValues(req, 'content-type');
    const out = await service.handle({
      contentType: types.length === 1 ? types[0] : undefined,
      voucherHeaders: rawValues(req, 'x-lab-voucher'),
      body: Uint8Array.from(Buffer.concat(chunks)),
    });
    reply(res, out.status, out.contentType, out.body, {}, out.status >= 500 && out.status !== 503);
  }
  return server;
}
