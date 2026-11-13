import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const assets = new Map([
  ['/', { type: 'text/html; charset=utf-8', body: readFileSync(new URL('../static/index.html', import.meta.url)) }],
  ['/style.css', { type: 'text/css; charset=utf-8', body: readFileSync(new URL('../static/style.css', import.meta.url)) }],
]);

/** Read-only layout preview. Live command handling awaits accepted K01 contracts. */
export async function startPreview(port = 4174) {
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw Error('preview-port-invalid');
  let actualPort = port;
  const server = createServer({ maxHeaderSize: 8192, requestTimeout: 5000 }, (request, response) => {
    const hosts = [`127.0.0.1:${actualPort}`, `localhost:${actualPort}`];
    const host = request.headers.host;
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    if (!hosts.includes(host)) {
      response.writeHead(421);
      response.end();
      return;
    }
    if (request.headers.origin && request.headers.origin !== `http://${host}`) {
      response.writeHead(403);
      response.end();
      return;
    }
    if (!['GET', 'HEAD'].includes(request.method)) {
      response.writeHead(405, { Allow: 'GET, HEAD' });
      response.end();
      return;
    }
    const asset = assets.get(request.url);
    if (!asset) {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { 'Content-Type': asset.type, 'Content-Length': String(asset.body.length) });
    response.end(request.method === 'HEAD' ? undefined : asset.body);
  });
  server.maxHeadersCount = 32;
  server.headersTimeout = 5000;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  actualPort = server.address().port;
  return { server, port: actualPort };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { server, port } = await startPreview();
  process.stdout.write(JSON.stringify({ event: 'portal-preview', host: '127.0.0.1', port }) + '\n');
  const stop = () => server.close();
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}
