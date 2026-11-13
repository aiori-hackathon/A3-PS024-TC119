import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPki } from '../src/pki.ts';
import { localReadiness } from '../src/controller/preflight.ts';
import { overlaps, checkNetworkConfiguration } from '../src/controller/network-readiness.ts';

test('subnet conflicts use ranges, including broader VPN routes; topology checks cannot substitute for live isolation',()=>{
  assert.equal(overlaps('172.28.0.0/16','172.28.40.0/24'),true);
  assert.equal(overlaps('172.28.39.0/24','172.28.40.0/24'),false);
  const networks=Object.fromEntries(['client_proxy','proxy_issuer','proxy_gateway','gateway_replay','gateway_origin'].map((name,i)=>[name,{internal:true,enable_ipv6:false,ipam:{config:[{subnet:`172.28.${(i+1)*10}.0/24`}]}}]));
  const config={networks,services:Object.fromEntries(Array.from({length:10},(_,i)=>[String(i),{}]))};
  assert.ok(checkNetworkConfiguration(config,[],[]).every(c=>c.ok));
  assert.equal(checkNetworkConfiguration(config,[],['172.28.0.1/16'])[1]!.ok,false);
  const foreign=[{Labels:{},IPAM:{Config:[{Subnet:'172.28.40.128/25'}]}}];
  assert.equal(checkNetworkConfiguration(config,foreign,[])[1]!.ok,false);
  config.networks.gateway_replay!.internal=false;
  assert.equal(checkNetworkConfiguration(config,[],[])[0]!.ok,false);
});

test('preflight detects expired certificates, wrong key pairs, invalid credentials and missing dependencies', t => {
  const root = mkdtempSync(join(tmpdir(), 'tf-preflight-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  writeFileSync(join(root, '.node-version'), process.versions.node);
  const pki = createPki('Preflight Test CA', 7);
  const put = (p: string, v: string) => { const path = join(root, '.runtime/secrets', p); mkdirSync(join(path, '..'), { recursive: true, mode: 0o700 }); writeFileSync(path, v); };
  put('client/ca.crt', pki.caPem);
  for (const [role, name] of [['issuer', 'issuer.lab.test'], ['gateway', 'origin.lab.test']]) {
    const leaf = pki.leaf(name!); put(`${role}/tls.crt`, leaf.cert); put(`${role}/tls.key`, leaf.key);
  }
  const password = 'a'.repeat(43); put('controller/redis-password', password); put('redis/redis-acl.conf', `user controller on >${password} ~* &* +@all\n`);
  const result = (name: string, now?: number) => localReadiness(root, now).find(c => c.check === name)!.ok;
  assert.equal(result('tls-validity-trust-and-key-pairs'), true);
  assert.equal(result('redis-credential-and-acl'), true);
  assert.equal(result('tls-validity-trust-and-key-pairs', Date.now() + 8 * 86400000), false);
  put('gateway/tls.key', pki.leaf('origin.lab.test').key);
  assert.equal(result('tls-validity-trust-and-key-pairs'), false);
  put('controller/redis-password', 'invalid'); assert.equal(result('redis-credential-and-acl'), false);
  assert.equal(result('lab-locked-dependencies'), false);
});
