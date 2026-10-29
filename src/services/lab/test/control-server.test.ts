import test from 'node:test';
import assert from 'node:assert/strict';
import { connect, type Server } from 'node:net';
import { mkdtempSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { serveControl } from '../src/control-server.ts';

const sockPath = () => process.platform === 'win32'
  ? ['', '', '.', 'pipe', `ps024-test-${randomBytes(6).toString('hex')}`].join(String.fromCharCode(92))
  : join(mkdtempSync(join(tmpdir(), 'ps024-')), 'control.sock');
const lines = (path: string) => {
  const s = connect(path); const got: any[] = []; let buf = '';
  s.setEncoding('utf8');
  s.on('data', (d: string) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { got.push(JSON.parse(buf.slice(0, i))); buf = buf.slice(i + 1); } });
  s.on('error', () => undefined);
  return { s, got };
};
const until = async (f: () => boolean) => { for (let i = 0; i < 200 && !f(); i++) await new Promise((r) => setTimeout(r, 10)); assert.ok(f(), 'condition not reached'); };
const open: Server[] = [];
test.after(() => { for (const s of open) s.close(); });

test('replies are correlated by request_id; a stalled command does not block FENCE or STATUS', async () => {
  const path = sockPath();
  let release!: () => void;
  const stalled = new Promise<void>((r) => { release = r; });
  open.push(await serveControl(path, async (raw) => {
    const r = raw as { request_id: string; command: string };
    if (r.command === 'RUN_SCENARIO') await stalled;
    return { request_id: r.request_id, command: r.command };
  }));
  const { s, got } = lines(path);
  s.write(JSON.stringify({ request_id: 'a', command: 'RUN_SCENARIO' }) + '\n');
  s.write(JSON.stringify({ request_id: 'b', command: 'FENCE' }) + '\n');
  s.write(JSON.stringify({ request_id: 'c', command: 'STATUS' }) + '\n');
  await until(() => got.length === 2);
  assert.deepEqual(got.map((g) => g.request_id).sort(), ['b', 'c']);
  release();
  await until(() => got.length === 3);
  assert.equal(got.at(-1).request_id, 'a');
  s.destroy();
});

test('non-JSON lines reach the handler as plain text (role returns a fixed error); oversize frames close the link', async () => {
  const path = sockPath();
  const seen: unknown[] = [];
  open.push(await serveControl(path, async (raw) => { seen.push(raw); return { ok: false }; }));
  const a = lines(path);
  a.s.write('not json\n');
  await until(() => a.got.length === 1);
  assert.deepEqual(seen, ['not json']);
  const b = lines(path);
  const closed = new Promise<void>((r) => b.s.on('close', () => r()));
  b.s.write('x'.repeat(65537) + '\n');
  await closed;
  a.s.destroy();
});

test('at most eight ordinary requests may be pending per connection; the ninth closes the link', async () => {
  const path = sockPath();
  open.push(await serveControl(path, () => new Promise(() => undefined)));
  const { s } = lines(path);
  const closed = new Promise<void>((r) => s.on('close', () => r()));
  for (let i = 0; i < 9; i++) s.write(JSON.stringify({ request_id: String(i), command: 'RUN_SCENARIO' }) + '\n');
  await closed;
});

test('socket file is owner-only on POSIX', { skip: process.platform === 'win32' }, async () => {
  const path = sockPath();
  open.push(await serveControl(path, async () => ({})));
  assert.equal(statSync(path).mode & 0o777, 0o600);
});
