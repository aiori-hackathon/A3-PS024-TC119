import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { request } from 'node:http';
import { hex } from '../../../contracts/lib/index.ts';
import { buildReport, type RunRecord } from '../src/report/build.ts';
import { esc, renderReport, startViewer, ViewerError } from '../src/report/serve.ts';

const run = (id: string): RunRecord => ({
  run_id: hex(randomBytes(16)), config_digest: hex(randomBytes(32)), token_key_id: hex(randomBytes(32)), gateway_profile: 'B1', client_profile: 'demo',
  origin_incarnation: hex(randomBytes(16)),
  scenario_results: [{ scenario_id: id, status: 'PASS', expected: 'accepted', counters: { protected_requests_received: 1 }, origin_counts_available: true, worker_verification_attempts: [], failure_labels: [] }],
  measurements: [], state_transitions: [{ state: 'ENABLED', reason: 'enabled' }], retention_checks: [],
});
const goodReport = () => JSON.stringify(buildReport({ kind: 'demo', runs: [run('healthy-flow')] }));

function get(port: number, path: string, o: { method?: string; host?: string } = {}): Promise<{ status: number; headers: Record<string, unknown>; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method: o.method ?? 'GET', headers: { Host: o.host ?? `127.0.0.1:${port}` } }, (res) => {
      let body = ''; res.setEncoding('utf8'); res.on('data', (c) => { body += c; }); res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body }));
    });
    req.on('error', reject); req.end();
  });
}
async function viewer(file: string) { const v = await startViewer(file, '127.0.0.1', 0); return { ...v, close: () => new Promise<void>((r) => v.server.close(() => r())) }; }
const dir = () => mkdtempSync(join(tmpdir(), 'viewer-'));

test('only loopback hosts and a valid port are accepted, and the report file must exist', async () => {
  const f = join(dir(), 'r.json'); writeFileSync(f, goodReport());
  for (const host of ['0.0.0.0', '::', '192.168.1.5', 'example.com', '']) assert.throws(() => startViewer(f, host, 0), (e: unknown) => e instanceof ViewerError && e.code === 'not-loopback', host);
  assert.throws(() => startViewer(f, '127.0.0.1', 70000), (e: unknown) => e instanceof ViewerError && e.code === 'bad-port');
  assert.throws(() => startViewer(join(dir(), 'missing.json'), '127.0.0.1', 0), (e: unknown) => e instanceof ViewerError && e.code === 'bad-file');
});

test('it serves the validated report with locked-down headers, and nothing else', async () => {
  const f = join(dir(), 'r.json'); writeFileSync(f, goodReport());
  const v = await viewer(f);
  try {
    const page = await get(v.port, '/');
    assert.equal(page.status, 200); assert.match(page.body, /healthy-flow/); assert.doesNotMatch(page.body, /<script/i);
    assert.match(String(page.headers['content-security-policy']), /default-src 'none'/);
    assert.equal(page.headers['x-content-type-options'], 'nosniff');
    assert.equal((await get(v.port, '/report.json')).status, 200);
    assert.equal((await get(v.port, '/style.css')).status, 200);
    for (const bad of ['/..%2f..%2fetc%2fpasswd', '/../package.json', '/r.json', '/report.json/../x', '/%2e%2e/secret', '/admin', '/api/run', '/docker']) assert.equal((await get(v.port, bad)).status, 404, bad);
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) assert.equal((await get(v.port, '/', { method })).status, 405, method);
    assert.equal((await get(v.port, '/', { method: 'HEAD' })).body, '');
    assert.equal((await get(v.port, '/', { host: 'evil.example' })).status, 421, 'DNS-rebinding style Host is refused');
    assert.equal((await get(v.port, '/?file=/etc/passwd')).status, 200, 'a query string never selects a file');
  } finally { await v.close(); }
});

test('a report that fails validation or carries address or token-like material is never shown; an atomic replacement is picked up', async () => {
  const d = dir(); const f = join(d, 'r.json');
  writeFileSync(f, '{"overall_status":"PASS"}');
  const v = await viewer(f);
  try {
    assert.equal((await get(v.port, '/')).status, 503);
    const leaky = JSON.parse(goodReport()); leaky.runs[0].scenario_results[0].failure_labels = ['10.0.0.1'];
    writeFileSync(join(d, 'n.json'), JSON.stringify(leaky)); renameSync(join(d, 'n.json'), f);
    assert.equal((await get(v.port, '/')).status, 503, 'privacy scan applies to what is displayed');
    writeFileSync(join(d, 'n.json'), goodReport()); renameSync(join(d, 'n.json'), f);
    assert.equal((await get(v.port, '/')).status, 200);
    writeFileSync(f, 'x'.repeat(2 * 1024 * 1024));
    assert.equal((await get(v.port, '/')).status, 503, 'oversized file is refused');
  } finally { await v.close(); }
});

test('everything rendered from the report is escaped', () => {
  assert.equal(esc(`<img src=x onerror="a()">&'\``), '&#60;img src=x onerror=&#34;a()&#34;&#62;&#38;&#39;&#96;');
  const rep = JSON.parse(goodReport()); rep.runs[0].scenario_results[0].scenario_id = '<script>alert(1)</script>'; rep.runs[0].scenario_results[0].failure_labels = ['"><b>x'];
  const html = renderReport(rep);
  assert.doesNotMatch(html, /<script>alert/); assert.doesNotMatch(html, /"><b>x/); assert.match(html, /&#60;script&#62;alert\(1\)/);
});
