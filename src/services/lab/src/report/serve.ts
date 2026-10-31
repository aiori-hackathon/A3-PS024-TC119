// serve-report: a read-only evidence viewer. It serves ONE report file, re-validated (schema, evidence rules, privacy scan) on
// every change, rendered on the server with every value escaped. It has no JavaScript, loads nothing from elsewhere, accepts
// only GET and HEAD on three fixed paths, and can listen only on loopback. It exposes no upload, no file other than the one it
// was started with, no command, no scenario execution and no Docker access. A report that fails validation is never shown.
import { createServer, type Server } from 'node:http';
import { readFileSync, statSync } from 'node:fs';
import { verifyReportText } from './verify.ts';

export class ViewerError extends Error {
  readonly code: 'not-loopback' | 'bad-port' | 'bad-file';
  constructor(code: 'not-loopback' | 'bad-port' | 'bad-file') { super(code); this.code = code; }
}
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost']);
const MAX_BYTES = 1024 * 1024;

export const esc = (v: unknown): string => String(v ?? '').replace(/[&<>"'`]/g, (c) => `&#${c.charCodeAt(0)};`);
const CSS = `body{font:15px/1.5 system-ui,sans-serif;margin:24px auto;max-width:1100px;padding:0 16px;color:#1b1f23;background:#fff}
h1{font-size:22px}h2{font-size:17px;margin-top:28px}table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid #d0d7de;padding:5px 8px;text-align:left;vertical-align:top;font-size:13px}th{background:#f6f8fa}
.PASS{color:#116329;font-weight:600}.FAIL{color:#a40e26;font-weight:600}.INCONCLUSIVE{color:#7d4e00;font-weight:600}
.note{color:#57606a;font-size:13px}code{font:12px ui-monospace,monospace}
@media (prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}th{background:#161b22}th,td{border-color:#30363d}.PASS{color:#56d364}.FAIL{color:#ff7b72}.INCONCLUSIVE{color:#e3b341}.note{color:#8b949e}}`;

type Json = Record<string, any>; // validated by verifyReportText before it reaches the renderer
const status = (s: unknown) => `<span class="${esc(s)}">${esc(s)}</span>`;
const counters = (c: Record<string, number>) => Object.entries(c).map(([k, v]) => `${esc(k)}=${esc(v)}`).join(' ');

export function renderReport(r: Json): string {
  const runs = (r['runs'] as Json[]).map((run, i) => {
    const scenarios = (run['scenario_results'] as Json[]).map((s) => `<tr><td>${esc(s['scenario_id'])}</td><td>${status(s['status'])}</td><td>${esc(s['expected'])}</td><td>${s['origin_counts_available'] ? 'available' : '<b>not available</b>'}</td><td>${counters(s['counters'] ?? {})}</td><td>${esc((s['failure_labels'] ?? []).join(', '))}</td></tr>`).join('\n');
    const retention = (run['retention_checks'] as Json[]);
    const measures = (run['measurements'] as Json[]);
    const q = (v: unknown) => (v === null ? 'beyond 5000' : esc(v));
    const measurementTable = measures.length ? `<table><tr><th>Metric</th><th>Samples</th><th>Failures</th><th>Elapsed ms</th><th>Samples/s</th><th>p50 ms</th><th>p95 ms</th><th>p99 ms</th></tr>${measures.map((m) => `<tr><td>${esc(m['metric'])}</td><td>${esc(m['count'])}</td><td>${esc(m['failures'])}</td><td>${esc(m['elapsed_ms'])}</td><td>${m['elapsed_ms'] > 0 ? esc((m['count'] / m['elapsed_ms'] * 1000).toFixed(1)) : 'n/a'}</td><td>${q(m['p50_ms'])}</td><td>${q(m['p95_ms'])}</td><td>${q(m['p99_ms'])}</td></tr>`).join('')}</table><p class="note">Quantiles are the upper bound of the histogram bucket they fall in.</p>` : '';
    return `<h2>Run ${i + 1}: ${esc(run['gateway_profile'])} gateway, ${esc(run['client_profile'])} clients</h2>
<p class="note">config digest <code>${esc(run['config_digest'])}</code> · token key id <code>${esc(run['token_key_id'])}</code></p>
<table><tr><th>Scenario</th><th>Status</th><th>Expected</th><th>Independent origin evidence</th><th>Counters</th><th>Labels</th></tr>
${scenarios}
</table>
${measurementTable}
${retention.length ? `<table><tr><th>Retention check</th><th>Status</th></tr>${retention.map((c) => `<tr><td>${esc(c['check_id'])}</td><td>${status(c['status'])}</td></tr>`).join('')}</table>` : ''}
<p class="note">${esc((run['state_transitions'] as Json[]).map((t) => t['state']).join(' > '))}</p>`;
  }).join('\n');
  const sw = r['software'] as Json, env = r['environment'] as Json;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="10"><title>TokenForge evidence report</title><link rel="stylesheet" href="/style.css"></head><body>
<h1>TokenForge evidence report</h1>
<p>Suite <b>${esc(r['suite_kind'])}</b> · overall ${status(r['overall_status'])} · created ${esc(r['created_at_utc'])} · contract ${esc(r['contract_version'])}</p>
<p class="note">Read-only view of a validated report file. A PASS needs every required scenario, each with independent origin evidence; this page only displays what the controller recorded.</p>
${runs}
<h2>Provenance</h2>
<p class="note">commit <code>${esc(sw['git_commit'])}</code>${sw['dirty'] ? ' (<b>working tree was dirty</b>)' : ''} · node ${esc(sw['node_version'])} · ${esc(env['os'])} · ${esc(env['cpu_count'])} CPUs · docker ${esc(env['docker_version'])} · ${esc(env['topology'])}</p>
</body></html>`;
}

const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cross-Origin-Resource-Policy': 'same-origin', 'Cache-Control': 'no-store',
} as const;

export function createViewer(file: string, listenPort: () => number): Server {
  let cached: { stamp: string; html: string; json: string } | null = null;
  const load = (): { html: string; json: string } | null => {
    try {
      const s = statSync(file);
      if (!s.isFile() || s.size > MAX_BYTES) return null;
      const stamp = `${s.mtimeMs}:${s.size}`;
      if (cached?.stamp === stamp) return cached;
      const text = readFileSync(file, 'utf8');
      if (!verifyReportText(text).ok) { cached = null; return null; }
      cached = { stamp, html: renderReport(JSON.parse(text) as Json), json: text };
      return cached;
    } catch { cached = null; return null; }
  };
  return createServer((req, res) => {
    const send = (code: number, type: string, body: string, extra: Record<string, string> = {}) => { res.writeHead(code, { ...SECURITY_HEADERS, 'Content-Type': type, ...extra }); res.end(req.method === 'HEAD' ? undefined : body); };
    const port = listenPort();
    // DNS-rebinding guard: only the loopback names on this exact port are accepted as the Host.
    if (!new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]).has(String(req.headers.host ?? ''))) return send(421, 'text/plain; charset=utf-8', 'misdirected request');
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(405, 'text/plain; charset=utf-8', 'method not allowed', { Allow: 'GET, HEAD' });
    const path = (req.url ?? '').split('?')[0]; // anything after '?' is ignored; no path is ever mapped to a file
    if (path === '/style.css') return send(200, 'text/css; charset=utf-8', CSS);
    if (path !== '/' && path !== '/report.json') return send(404, 'text/plain; charset=utf-8', 'not found');
    const report = load();
    if (!report) return send(503, 'text/plain; charset=utf-8', 'no valid report is available yet', { 'Retry-After': '5' });
    return path === '/' ? send(200, 'text/html; charset=utf-8', report.html) : send(200, 'application/json; charset=utf-8', report.json);
  });
}

/** Starts the viewer. The host must be loopback; anything else is refused before a socket exists. */
export function startViewer(file: string, host = '127.0.0.1', port = 4173): Promise<{ server: Server; host: string; port: number }> {
  if (!LOOPBACK.has(host)) throw new ViewerError('not-loopback');
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new ViewerError('bad-port');
  try { if (!statSync(file).isFile()) throw new Error(); } catch { throw new ViewerError('bad-file'); }
  let bound = port;
  const server = createViewer(file, () => bound);
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ host: host === 'localhost' ? '127.0.0.1' : host, port }, () => { bound = (server.address() as { port: number }).port; resolve({ server, host, port: bound }); });
  });
}
