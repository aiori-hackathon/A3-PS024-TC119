import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, ECDH } from 'node:crypto';

test('vendored source and correction patch match recorded provenance', () => {
  const provenance = JSON.parse(readFileSync(new URL('../vendor/provenance.json', import.meta.url)));
  const patch = readFileSync(new URL('../vendor/arc-input-validation.patch', import.meta.url), 'utf8').replaceAll('\r\n', '\n');
  assert.equal(createHash('sha256').update(patch).digest('hex'), provenance.patch_sha256);
  for (const file of provenance.files) {
    const bytes = readFileSync(new URL(`../vendor/arc/${file.path}`, import.meta.url), 'utf8').replaceAll('\r\n', '\n');
    assert.equal(createHash('sha256').update(bytes).digest('hex'), file.sha256, file.path);
  }
});

test('canonical public bootstrap parameters match the real upstream vector', () => {
  const fixture = JSON.parse(readFileSync(new URL('../fixtures/public-parameters.json', import.meta.url)));
  const vector = JSON.parse(readFileSync(new URL('../vendor/arc/tests/vectors/arc_v01.json', import.meta.url)));
  const server = vector['ARCV1-P256'].ServerKey;
  const expected = Buffer.concat([server.X0, server.X1, server.X2].map(point => Buffer.from(point, 'hex')));
  const bytes = Buffer.from(fixture.issuer_params_b64url, 'base64url');
  assert.equal(bytes.length, 99);
  assert.equal(bytes.toString('base64url'), fixture.issuer_params_b64url);
  assert.ok(bytes.equals(expected));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), fixture.arc_key_id);
  for (let offset = 0; offset < bytes.length; offset += 33) {
    const point = bytes.subarray(offset, offset + 33);
    assert.ok([2, 3].includes(point[0]));
    const canonical = ECDH.convertKey(point, 'prime256v1', undefined, undefined, 'compressed');
    assert.ok(point.equals(canonical));
  }
});
