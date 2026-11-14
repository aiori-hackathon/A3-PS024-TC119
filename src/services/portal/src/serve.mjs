import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const assets = new Map([
  ['/', { type: 'text/html; charset=utf-8', body: readFileSync(new URL('../static/index.html', import.meta.url)) }],
  ['/style.css', { type: 'text/css; charset=utf-8', body: readFileSync(new URL('../static/style.css', import.meta.url)) }],
  ['/app.js', { type: 'text/javascript; charset=utf-8', body: readFileSync(new URL('../static/app.js', import.meta.url)) }],
]);
const profiles = ['ip', 'type2-bearer', 'arc', 'type2-holder'];
const clientIds = ['A', 'B', 'C', 'D', 'E'];
const maxBodyBytes = 4096;
const maxResponseBytes = 262144;
const sessionLifetime = 8 * 60 * 60 * 1000;
const operationLifetime = 2 * 60 * 1000;

function validCommand(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort().join(',');
  if (value.action === 'start_run') return keys === 'action,profile' && profiles.includes(value.profile);
  if (['reset_run', 'run_comparison', 'run_theft_scene'].includes(value.action)) return keys === 'action,revision' && Number.isSafeInteger(value.revision) && value.revision >= 0;
  return ['acquire', 'access'].includes(value.action) && keys === 'action,clientId,revision'
    && clientIds.includes(value.clientId) && Number.isSafeInteger(value.revision) && value.revision >= 0;
}

function publicJson(value) {
  const body = JSON.stringify(value);
  if (!body || Buffer.byteLength(body) > maxResponseBytes) throw Error('response-bound');
  return body;
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    request.on('data', chunk => {
      size += chunk.length;
      if (size > maxBodyBytes) {
        reject(Error('body-too-large'));
        request.resume();
      } else chunks.push(chunk);
    });
    request.on('end', () => {
      if (size > maxBodyBytes) return;
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(Error('body-invalid')); }
    });
    request.on('error', reject);
  });
}

/** The injected backend returns only its reviewed, secret-free public projection. */
export async function startPortal({ port = 4174, backend } = {}) {
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw Error('portal-port-invalid');
  if (backend && (typeof backend.status !== 'function' || typeof backend.execute !== 'function')) throw Error('portal-backend-invalid');
  const sessions = new Map();
  const operations = new Map();
  let busy = false;
  let activeStatusRequests = 0;
  let actualPort = port;
  const prune = () => {
    const now = Date.now();
    for (const [key, session] of sessions) if (session.expiresAt <= now) sessions.delete(key);
    for (const [key, operation] of operations) {
      if (operation.state !== 'pending' && operation.expiresAt <= now) {
        clearTimeout(operation.expiryTimer);
        operations.delete(key);
      }
    }
    while ([...operations.values()].filter(item => item.state !== 'pending').length > 8) {
      const oldest = [...operations].find(([, item]) => item.state !== 'pending');
      if (!oldest) break;
      clearTimeout(oldest[1].expiryTimer);
      operations.delete(oldest[0]);
    }
  };
  const server = createServer({ maxHeaderSize: 8192, requestTimeout: 5000 }, async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    const send = (code, value) => {
      if (response.writableEnded) return;
      let body;
      try { body = publicJson(value); }
      catch {
        code = 503;
        body = '{"error":"response-unavailable"}';
      }
      response.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) });
      response.end(request.method === 'HEAD' ? undefined : body);
    };
    const host = request.headers.host;
    if (![ `127.0.0.1:${actualPort}`, `localhost:${actualPort}` ].includes(host)) return send(421, { error: 'host-rejected' });
    if (request.headers.origin && request.headers.origin !== `http://${host}`) return send(403, { error: 'origin-rejected' });
    if (request.headers['sec-fetch-site'] === 'cross-site') return send(403, { error: 'origin-rejected' });
    const asset = assets.get(request.url);
    if (asset && ['GET', 'HEAD'].includes(request.method)) {
      response.writeHead(200, { 'Content-Type': asset.type, 'Content-Length': asset.body.length });
      response.end(request.method === 'HEAD' ? undefined : asset.body);
      return;
    }
    if (!backend) {
      if (!['GET', 'HEAD'].includes(request.method)) {
        response.setHeader('Allow', 'GET, HEAD');
        return send(405, { error: 'preview-read-only' });
      }
      if (request.url === '/api/status') return send(200, { mode: 'preview', state: 'idle', profile: null, revision: 0, clients: [] });
      return send(404, { error: 'not-found' });
    }
    prune();
    const sessionId = /(?:^|;\s*)portal_session=([a-f0-9]{64})(?:;|$)/.exec(request.headers.cookie ?? '')?.[1];
    let session = sessions.get(sessionId);
    if (request.url === '/api/status' && request.method === 'GET') {
      if (activeStatusRequests >= 4) return send(503, { error: 'status-capacity' });
      if (!session) {
        if (sessions.size >= 64) return send(503, { error: 'session-capacity' });
        const id = randomBytes(32).toString('hex');
        session = { id, token: randomBytes(32).toString('hex'), expiresAt: Date.now() + sessionLifetime };
        sessions.set(id, session);
        response.setHeader('Set-Cookie', `portal_session=${id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${sessionLifetime / 1000}`);
      }
      activeStatusRequests++;
      try {
        const status = await backend.status();
        return send(200, { ...status, mode: 'live', csrfToken: session.token });
      } catch { return send(503, { error: 'status-unavailable' }); }
      finally { activeStatusRequests--; }
    }
    if (request.url?.startsWith('/api/operations/') && request.method === 'GET') {
      if (!session) return send(403, { error: 'session-required' });
      const id = request.url.slice('/api/operations/'.length);
      if (!/^[a-f0-9]{48}$/.test(id)) return send(404, { error: 'operation-not-found' });
      const operation = operations.get(id);
      if (!operation || operation.sessionId !== session.id) return send(404, { error: 'operation-not-found' });
      return send(200, { operationId: id, state: operation.state, result: operation.result });
    }
    if (request.url !== '/api/command') {
      if (!['GET', 'HEAD'].includes(request.method)) response.setHeader('Allow', 'GET, HEAD');
      return send(['GET', 'HEAD'].includes(request.method) ? 404 : 405, { error: 'not-found' });
    }
    if (request.method !== 'POST') {
      response.setHeader('Allow', 'POST');
      return send(405, { error: 'method-rejected' });
    }
    if (request.headers.origin !== `http://${host}`) return send(403, { error: 'origin-required' });
    const token = request.headers['x-csrf-token'];
    if (!session || typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token) || !timingSafeEqual(Buffer.from(token), Buffer.from(session.token))) return send(403, { error: 'csrf-rejected' });
    if (request.headers['content-type'] !== 'application/json') return send(415, { error: 'content-type-rejected' });
    if (Number(request.headers['content-length'] ?? 0) > maxBodyBytes) return send(413, { error: 'body-too-large' });
    let command;
    try { command = await readBody(request); }
    catch (error) { return send(error.message === 'body-too-large' ? 413 : 400, { error: 'command-invalid' }); }
    if (!validCommand(command)) return send(400, { error: 'command-invalid' });
    if (busy) return send(409, { error: 'operation-in-progress' });
    const id = randomBytes(24).toString('hex');
    const operation = { sessionId: session.id, state: 'pending', expiresAt: Date.now() + operationLifetime };
    operations.set(id, operation);
    busy = true;
    send(202, { operationId: id, state: 'pending' });
    Promise.resolve().then(() => backend.execute(command)).then(result => {
      const projected = {
        outcome: result?.outcome,
        message: result?.message,
        authorizedAccess: command.action === 'access' ? result?.authorizedAccess : undefined,
        status: result?.status,
      };
      publicJson({ operationId: id, state: 'complete', result: projected });
      operation.state = 'complete';
      operation.result = projected;
    }).catch(() => {
      operation.state = 'uncertain';
      operation.result = { outcome: 'operation-uncertain', message: 'The operation could not be confirmed. Refresh server status before taking another action.' };
    }).finally(() => {
      operation.expiresAt = Date.now() + operationLifetime;
      operation.expiryTimer = setTimeout(() => operations.delete(id), operationLifetime);
      operation.expiryTimer.unref();
      busy = false;
      prune();
    });
  });
  server.maxHeadersCount = 32;
  server.maxConnections = 64;
  server.headersTimeout = 5000;
  server.once('close', () => {
    for (const operation of operations.values()) clearTimeout(operation.expiryTimer);
    operations.clear();
    sessions.clear();
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  actualPort = server.address().port;
  return { server, port: actualPort };
}

export async function startPreview(port = 4174) { return startPortal({ port }); }

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { server, port } = await startPreview();
  process.stdout.write(JSON.stringify({ event: 'portal-preview', host: '127.0.0.1', port }) + '\n');
  const stop = () => server.close();
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}
