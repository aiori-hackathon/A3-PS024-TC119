import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPki } from '../src/pki.ts';
import { localReadiness, supportedVersion } from '../src/controller/preflight.ts';
import { overlaps, checkNetworkConfiguration } from '../src/controller/network-readiness.ts';

function topology(regional = false): any {
  const names = ['client_proxy','proxy_issuer','proxy_gateway','gateway_replay','gateway_origin', ...(regional ? ['arc_private'] : [])];
  const networks = Object.fromEntries(names.map((name,index) => [name, { driver:'bridge', internal:true, enable_ipv6:false,
    ipam:{ config:[{ subnet:`172.28.${(index + 1) * 10}.0/24` }] } }]));
  const membership: Record<string,Record<string,string>> = {
    proxy: { client_proxy:'172.28.10.2', proxy_issuer:'172.28.20.2', proxy_gateway:'172.28.30.2' },
    issuer: { proxy_issuer:'172.28.20.10' },
    gateway: { proxy_gateway:'172.28.30.10', gateway_replay:'172.28.40.20', gateway_origin:'172.28.50.20' },
    redis: { gateway_replay:'172.28.40.10' },
    'protected-origin': { gateway_origin:'172.28.50.10' },
  };
  for (const [index, id] of ['a','b','c','d','e'].entries()) membership[`client-${id}`] = { client_proxy:`172.28.10.${11 + index}` };
  if (regional) {
    membership.issuer!.arc_private = '172.28.60.20';
    membership.gateway!.arc_private = '172.28.60.30';
    membership.arc = { arc_private:'172.28.60.10' };
  }
  const services = Object.fromEntries(Object.entries(membership).map(([name, links]) => [name, {
    networks:Object.fromEntries(Object.entries(links).map(([network, address]) => [network,{ ipv4_address:address }])),
    ...(name === 'arc' ? { profiles:['regional'] } : {}),
  }]));
  return { networks, services };
}

test('subnet conflicts use ranges, including broader VPN routes; topology checks cannot substitute for live isolation',()=>{
  assert.equal(overlaps('172.28.0.0/16','172.28.40.0/24'),true);
  assert.equal(overlaps('172.28.39.0/24','172.28.40.0/24'),false);
  const config=topology();
  assert.ok(checkNetworkConfiguration(config,[],[]).every(c=>c.ok));
  assert.equal(checkNetworkConfiguration(config,[],['172.28.0.1/16'])[1]!.ok,false);
  const foreign=[{Labels:{},IPAM:{Config:[{Subnet:'172.28.40.128/25'}]}}];
  assert.equal(checkNetworkConfiguration(config,foreign,[])[1]!.ok,false);
  config.networks.gateway_replay!.internal=false;
  assert.equal(checkNetworkConfiguration(config,[],[])[0]!.ok,false);
});

test('regional topology permits only its fixed private bridge and profile-gated ARC service', () => {
  const valid = topology(true);
  const accepted = (config:any) => checkNetworkConfiguration(config, [], [])[0]!.ok;
  assert.equal(accepted(valid), true);
  for (const change of [
    (config:any) => { config.networks.extra = structuredClone(config.networks.arc_private); },
    (config:any) => { config.networks.arc_private.ipam.config[0].subnet = '172.28.70.0/24'; },
    (config:any) => { config.networks.arc_private.internal = false; },
    (config:any) => { config.services.extra = structuredClone(config.services.arc); },
    (config:any) => { config.services.arc.profiles = []; },
    (config:any) => { delete config.services.arc; },
    (config:any) => { config.services.arc.ports = [{ target:7101, published:'7101' }]; },
    (config:any) => { config.services.gateway.network_mode = 'host'; },
    (config:any) => { config.services.arc.network_mode = 'service:gateway'; },
    (config:any) => { config.services['client-a'].networks.arc_private = { ipv4_address:'172.28.60.50' }; },
    (config:any) => { config.services.arc.networks.gateway_replay = { ipv4_address:'172.28.40.50' }; },
    (config:any) => { config.services.issuer.networks.arc_private.ipv4_address = '172.28.60.21'; },
  ]) {
    const altered = structuredClone(valid);
    change(altered);
    assert.equal(accepted(altered), false);
  }
  assert.equal(checkNetworkConfiguration(valid, [], ['172.28.60.1/24'])[1]!.ok, false);
});

test('version checks accept supported CI and desktop patches and reject lower/malformed versions',()=>{
  assert.equal(supportedVersion('28.0.4',[28,0,4]),true);
  assert.equal(supportedVersion('29.4.0',[28,0,4]),true);
  assert.equal(supportedVersion('v2.38.2',[2,38,2]),true);
  assert.equal(supportedVersion('5.1.1',[2,38,2]),true);
  assert.equal(supportedVersion('2.38.1',[2,38,2]),false);
  assert.equal(supportedVersion('unavailable',[28,0,4]),false);
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
