import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { startPreview } from '../src/serve.mjs';

function fetchPreview(port, path = '/', headers = {}, method = 'GET') {
  return new Promise((resolve, reject) => {
    const call = request({ host: '127.0.0.1', port, path, headers, method }, response => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { body += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body }));
    });
    call.on('error', reject);
    call.end();
  });
}

test('preview labels pending actions and serves only its fixed assets on loopback', async t => {
  const { server, port } = await startPreview(0);
  t.after(() => new Promise(resolve => server.close(resolve)));
  assert.equal(server.address().address, '127.0.0.1');
  const page = await fetchPreview(port);
  assert.equal(page.status, 200);
  assert.match(page.body, /Layout preview/);
  assert.match(page.body, /<button disabled>Acquire allowance/);
  assert.match(page.body, /<button class="primary" disabled>Access resource/);
  assert.match(page.body, /<fieldset disabled>/);
  assert.equal((page.body.match(/<th scope="row">Client /g) ?? []).length, 5);
  assert.equal(page.headers['cache-control'], 'no-store');
  assert.match(page.headers['content-security-policy'], /form-action 'none'/);
  assert.equal((await fetchPreview(port, '/style.css')).status, 200);
  assert.equal((await fetchPreview(port, '/', {}, 'HEAD')).body, '');
  for (const path of ['/resource', '/report.json', '/../../.runtime/secrets', '/?file=secret']) {
    assert.equal((await fetchPreview(port, path)).status, 404);
  }
});

test('foreign Host/Origin and action methods are rejected', async t => {
  const { server, port } = await startPreview(0);
  t.after(() => new Promise(resolve => server.close(resolve)));
  assert.equal((await fetchPreview(port, '/', { Host: 'attacker.example' })).status, 421);
  assert.equal((await fetchPreview(port, '/', { Origin: 'https://attacker.example' })).status, 403);
  assert.equal((await fetchPreview(port, '/', { Origin: `http://127.0.0.1:${port}` })).status, 200);
  for (const method of ['POST', 'PUT', 'DELETE']) assert.equal((await fetchPreview(port, '/', {}, method)).status, 405);
});
