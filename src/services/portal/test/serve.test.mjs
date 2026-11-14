import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { startPortal, startPreview } from '../src/serve.mjs';

function fetchPortal(port, path = '/', headers = {}, method = 'GET', body) {
  return new Promise((resolve, reject) => {
    const call = request({ host: '127.0.0.1', port, path, headers, method }, response => {
      let text = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { text += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: text, json: () => JSON.parse(text) }));
    });
    call.on('error', reject);
    call.end(body);
  });
}

const publicStatus = () => ({ mode: 'live', observedAt: new Date().toISOString(), state: 'active', profile: 'arc', revision: 3, clients: [{ clientId: 'A', estimatedUsesLeft: 2, state: 'ready' }] });
async function setup(t, execute = async () => ({ outcome: 'delivered', authorizedAccess: { clientId: 'A', text: 'Authorized research brief.' } })) {
  const portal = await startPortal({ port: 0, backend: { status: async () => publicStatus(), execute } });
  t.after(() => new Promise(resolve => portal.server.close(resolve)));
  const response = await fetchPortal(portal.port, '/api/status');
  const session = response.headers['set-cookie'][0].split(';')[0];
  const headers = { Cookie: session, Origin: `http://127.0.0.1:${portal.port}`, 'X-CSRF-Token': response.json().csrfToken, 'Content-Type': 'application/json' };
  return { ...portal, headers };
}
async function operationResult(port, headers, operationId) {
  for (let attempt = 0; attempt < 30; attempt++) {
    const response = await fetchPortal(port, `/api/operations/${operationId}`, headers);
    if (response.json().state !== 'pending') return response;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  throw Error('operation-did-not-settle');
}

test('preview serves fixed assets on loopback with honest empty state and disabled controls', async t => {
  const { server, port } = await startPreview(0);
  t.after(() => new Promise(resolve => server.close(resolve)));
  assert.equal(server.address().address, '127.0.0.1');
  const page = await fetchPortal(port);
  assert.equal(page.status, 200);
  assert.match(page.body, /Layout preview/);
  assert.match(page.body, /id="acquire" disabled>Acquire allowance/);
  assert.match(page.body, /id="access" class="primary" disabled>Access resource/);
  assert.match(page.body, /<fieldset id="profiles" disabled>/);
  assert.equal((page.body.match(/<th scope="row">Client /g) ?? []).length, 5);
  assert.equal(page.headers['cache-control'], 'no-store');
  assert.match(page.headers['content-security-policy'], /script-src 'self'; connect-src 'self'/);
  assert.equal((await fetchPortal(port, '/style.css')).status, 200);
  assert.equal((await fetchPortal(port, '/app.js')).status, 200);
  assert.equal((await fetchPortal(port, '/', {}, 'HEAD')).body, '');
  assert.equal((await fetchPortal(port, '/api/status')).json().mode, 'preview');
  for (const path of ['/resource', '/report.json', '/../../.runtime/secrets', '/?file=secret']) assert.equal((await fetchPortal(port, path)).status, 404);
});

test('foreign Host/Origin and preview mutation methods are rejected', async t => {
  const { server, port } = await startPreview(0);
  t.after(() => new Promise(resolve => server.close(resolve)));
  assert.equal((await fetchPortal(port, '/', { Host: 'attacker.example' })).status, 421);
  assert.equal((await fetchPortal(port, '/', { Origin: 'https://attacker.example' })).status, 403);
  assert.equal((await fetchPortal(port, '/', { Origin: `http://127.0.0.1:${port}` })).status, 200);
  for (const method of ['POST', 'PUT', 'DELETE']) assert.equal((await fetchPortal(port, '/', {}, method)).status, 405);
});

test('live commands require same-origin session and CSRF and strict content type', async t => {
  let calls = 0;
  const { port, headers } = await setup(t, async () => { calls++; return { outcome: 'started' }; });
  const body = JSON.stringify({ action: 'start_run', profile: 'arc' });
  for (const changes of [{ Origin: undefined }, { Origin: 'https://attacker.example' }, { Host: 'attacker.example' }, { Cookie: undefined }, { 'X-CSRF-Token': undefined }, { 'X-CSRF-Token': 'a'.repeat(63) }, { 'X-CSRF-Token': 'é'.repeat(64) }, { 'Sec-Fetch-Site': 'cross-site' }]) {
    const changed = { ...headers, ...changes };
    for (const key of Object.keys(changed)) if (changed[key] === undefined) delete changed[key];
    const result = await fetchPortal(port, '/api/command', changed, 'POST', body);
    assert.ok([403, 421].includes(result.status));
  }
  assert.equal((await fetchPortal(port, '/api/command', { ...headers, 'Content-Type': 'text/plain' }, 'POST', body)).status, 415);
  assert.equal(calls, 0);
  const result = await fetchPortal(port, '/api/command', headers, 'POST', body);
  assert.equal(result.status, 202);
  assert.equal((await operationResult(port, headers, result.json().operationId)).json().result.outcome, 'started');
  assert.equal(calls, 1);
});

test('only exact bounded fixed commands reach backend', async t => {
  let calls = 0;
  const { port, headers } = await setup(t, async () => { calls++; return { outcome: 'reset' }; });
  const bad = [null, [], {}, { action: 'shell', command: 'anything' }, { action: 'start_run', profile: 'other' }, { action: 'start_run', profile: 'arc', file: 'secret' }, { action: 'acquire', clientId: 'F', revision: 0 }, { action: 'access', clientId: 'A', revision: -1 }, { action: 'access', clientId: 'A', revision: 1.5 }, { action: 'reset_run' }, { action: 'run_comparison', revision: 0, extra: true }];
  for (const command of bad) assert.equal((await fetchPortal(port, '/api/command', headers, 'POST', JSON.stringify(command))).status, 400);
  assert.equal((await fetchPortal(port, '/api/command', headers, 'POST', '{')).status, 400);
  assert.equal((await fetchPortal(port, '/api/command', headers, 'POST', 'x'.repeat(4097))).status, 413);
  assert.equal(calls, 0);
  for (const command of [{ action: 'reset_run', revision: 0 }, { action: 'run_comparison', revision: 0 }, { action: 'run_theft_scene', revision: 0 }, { action: 'acquire', clientId: 'E', revision: 0 }]) {
    const response = await fetchPortal(port, '/api/command', headers, 'POST', JSON.stringify(command));
    assert.equal(response.status, 202);
    await operationResult(port, headers, response.json().operationId);
  }
  assert.equal(calls, 4);
});

test('operations are session-scoped, asynchronous and single-flight with authorized resource only on access', async t => {
  let finish;
  const { port, headers } = await setup(t, () => new Promise(resolve => { finish = resolve; }));
  const body = JSON.stringify({ action: 'access', clientId: 'A', revision: 3 });
  const accepted = await fetchPortal(port, '/api/command', headers, 'POST', body);
  const id = accepted.json().operationId;
  assert.match(id, /^[a-f0-9]{48}$/);
  assert.equal((await fetchPortal(port, `/api/operations/${id}`, headers)).json().state, 'pending');
  assert.equal((await fetchPortal(port, '/api/command', headers, 'POST', body)).status, 409);
  assert.equal((await fetchPortal(port, `/api/operations/${id}`)).status, 403);
  const other = await fetchPortal(port, '/api/status');
  assert.equal((await fetchPortal(port, `/api/operations/${id}`, { Cookie: other.headers['set-cookie'][0].split(';')[0] })).status, 404);
  finish({ outcome: 'delivered', authorizedAccess: { clientId: 'A', text: 'Protected content.' }, arbitrarySecret: 'private-never-serialize' });
  const complete = await operationResult(port, headers, id);
  assert.equal(complete.json().result.authorizedAccess.text, 'Protected content.');
  assert.doesNotMatch(complete.body, /private-never-serialize/);
});

test('backend exceptions and oversized responses become fixed safe errors', async t => {
  const { port, headers } = await setup(t, async () => { throw Error('private-key-secret'); });
  const accepted = await fetchPortal(port, '/api/command', headers, 'POST', JSON.stringify({ action: 'reset_run', revision: 3 }));
  const complete = await operationResult(port, headers, accepted.json().operationId);
  assert.equal(complete.json().state, 'uncertain');
  assert.doesNotMatch(complete.body, /private-key-secret/);
  const huge = await startPortal({ port: 0, backend: { status: async () => ({ value: 'x'.repeat(300000) }), execute: async () => ({}) } });
  t.after(() => new Promise(resolve => huge.server.close(resolve)));
  assert.equal((await fetchPortal(huge.port, '/api/status')).status, 503);
});

test('resource is omitted from setup result and completed retention is bounded', async t => {
  const { port, headers } = await setup(t, async () => ({ outcome: 'reset', authorizedAccess: { clientId: 'A', text: 'Protected content.' } }));
  const ids = [];
  for (let index = 0; index < 10; index++) {
    const accepted = await fetchPortal(port, '/api/command', headers, 'POST', JSON.stringify({ action: 'reset_run', revision: 3 }));
    ids.push(accepted.json().operationId);
    const result = await operationResult(port, headers, ids.at(-1));
    assert.equal(result.json().result.authorizedAccess, undefined);
  }
  assert.equal((await fetchPortal(port, `/api/operations/${ids[0]}`, headers)).status, 404);
  assert.equal((await fetchPortal(port, `/api/operations/${ids.at(-1)}`, headers)).status, 200);
});

test('status reads are bounded while the backend is pending', async t => {
  let resolveStatus;
  const backend = { status: () => new Promise(resolve => { resolveStatus = resolve; }), execute: async () => ({}) };
  const { server, port } = await startPortal({ port: 0, backend });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const waiting = [];
  const resolvers = [];
  for (let index = 0; index < 4; index++) {
    waiting.push(fetchPortal(port, '/api/status'));
    while (resolvers.length <= index) {
      await new Promise(resolve => setTimeout(resolve, 1));
      if (resolveStatus) { resolvers.push(resolveStatus); resolveStatus = undefined; }
    }
  }
  assert.equal((await fetchPortal(port, '/api/status')).status, 503);
  for (const resolve of resolvers) resolve(publicStatus());
  const results = await Promise.all(waiting);
  assert.ok(results.every(result => result.status === 200));
});

test('an oversized operation result is uncertain and safe to retrieve', async t => {
  const { port, headers } = await setup(t, async () => ({ outcome: 'delivered', message: 'x'.repeat(262144) }));
  const accepted = await fetchPortal(port, '/api/command', headers, 'POST', JSON.stringify({ action: 'access', clientId: 'A', revision: 3 }));
  const response = await operationResult(port, headers, accepted.json().operationId);
  assert.equal(response.status, 200);
  assert.equal(response.json().state, 'uncertain');
});
