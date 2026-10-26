// Run after `npm run build`. Confirms the lab bundle is self-contained with respect to project source.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const dist = new URL('../dist/', import.meta.url);

test('dist holds only the bootstrap bundle and no gateway/fixture/test source', () => {
  assert.deepEqual(readdirSync(dist), ['bootstrap.mjs']);
  const text = readFileSync(new URL('bootstrap.mjs', dist), 'utf8');
  assert.match(text, /PS024-context-v1/, 'shared contract is bundled');
  assert.doesNotMatch(text, /services[\\/]gateway/i);
  assert.doesNotMatch(text, /policy-golden|rfc9578-public/);
});

test('bundle runs standalone: real issuance and public verification', () => {
  const r = spawnSync(process.execPath, [fileURLToPath(new URL('bootstrap.mjs', dist))], { encoding: 'utf8', timeout: 60000 });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.deepEqual([out.component, out.contract_version, out.request_bytes, out.token_bytes, out.verified],
    ['lab-contract-bootstrap', 'TF-PS024-1.0.0', 259, 354, true]);
  assert.equal(out.node_major, 24);
  assert.equal(JSON.stringify(out).includes('PRIVATE'), false);
});
