import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// Execute the actual UI module with a minimal DOM and the public command transport.
test('expired allowance retains evidence, disables access and permits explicit renewal or stop', async () => {
  const elements = new Map();
  const el = id => {
    if (!elements.has(id)) elements.set(id, { value: 'A', textContent: '', disabled: false,
      handlers: {}, append() {}, replaceChildren() {}, addEventListener(event, fn) { this.handlers[event] = fn; } });
    return elements.get(id);
  };
  const document = { getElementById: el, createElement: () => ({ append() {} }),
    querySelector: () => ({ value: 'arc' }) };
  let current = { mode: 'live', state: 'expired', profile: 'arc', revision: 4,
    window: { label: 'Five-minute manual allowance', endsAt: new Date(Date.now() - 1000).toISOString() },
    evidence: { observedAt: new Date().toISOString(), state: 'verified', requestsReceived: 5, resourcesServed: 5, generationMismatches: 0 } };
  const commands = [];
  const fetch = async (path, init) => {
    if (path === '/api/status') return { ok: true, json: async () => current };
    if (path === '/api/command') {
      const body = JSON.parse(init.body); commands.push(body);
      current = { ...current, state: body.action === 'start_run' ? 'active' : 'idle', revision: current.revision + 1,
        window: body.action === 'start_run' ? { label: 'Five-minute manual allowance', endsAt: new Date(Date.now() + 300000).toISOString() } : undefined };
      return { ok: true, json: async () => ({ operationId: 'a'.repeat(48) }) };
    }
    return { ok: true, json: async () => ({ state: 'complete', result: { status: current } }) };
  };
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  await new AsyncFunction('document', 'fetch', 'setInterval', 'setTimeout',
    readFileSync(new URL('../static/app.js', import.meta.url), 'utf8'))(
    document, fetch, () => {}, fn => { queueMicrotask(fn); });
  assert.equal(el('server-state').textContent, 'Allowance expired');
  assert.match(el('window').textContent, /expired/);
  assert.equal(el('received').textContent, '5');
  assert.equal(el('access').disabled, true);
  assert.equal(el('acquire').disabled, true);
  assert.equal(el('start').disabled, false);
  assert.equal(el('start').textContent, 'Start new window');
  assert.equal(el('reset').disabled, false);
  assert.equal(commands.length, 0, 'expiry must not automatically issue a fresh allowance');
  await el('start').handlers.click();
  assert.deepEqual(commands[0], { action: 'start_run', profile: 'arc' });
  assert.equal(el('access').disabled, false);
  assert.match(el('window').textContent, /[45]:[0-5][0-9] left/);
  await el('reset').handlers.click();
  assert.deepEqual(commands[1], { action: 'reset_run', revision: 5 });
  assert.equal(el('server-state').textContent, 'idle');
});
