// A small real-issuer rig for client tests: genuine IssuerRole (TLS 1.3, real blind signing) behind a stub CONNECT proxy,
// plus a stub gateway. Everything is in-process and in memory.
import { randomBytes } from 'node:crypto';
import {
  PROTOCOL, makeManifest, configurationDigest, encodeBase64Url, voucherDigest, hex, type Manifest,
} from '../../../../contracts/lib/index.ts';
import { IssuerRole } from '../../src/issuer/control.ts';
import { ClientVouchers } from '../../src/client/vouchers.ts';
import { LabClient, type ClientConfig } from '../../src/client/client.ts';
import { createPki } from './pki.ts';
import { startGateway, startProxy, type StubGateway, type StubProxy } from './stubs.ts';

export type Rig = {
  pki: ReturnType<typeof createPki>; role: IssuerRole; manifest: Manifest; vouchers: Buffer[]; gateway: StubGateway; proxy: StubProxy;
  client: (over?: Partial<ClientConfig>) => LabClient; clientVouchers: () => ClientVouchers; stop: () => Promise<void>;
};

export async function startRig(count = 6): Promise<Rig> {
  const pki = createPki();
  const issuerTls = pki.leaf(PROTOCOL.issuer_name);
  const gatewayTls = pki.leaf(PROTOCOL.origin_name);
  const files: Record<string, string> = { '/run/secrets/tls.crt': issuerTls.cert, '/run/secrets/tls.key': issuerTls.key };
  const role = new IssuerRole({ readSecret: (p) => Buffer.from(files[p] ?? (() => { throw new Error('missing'); })()), clock: () => 1000,
    listen: { host: '127.0.0.1', port: 0 }, drainMs: 500 });
  const runId = hex(randomBytes(16));
  const send = (command: string, payload: object = {}, over: object = {}) => role.handle({ version: 1, request_id: hex(randomBytes(16)), command, run_id: runId,
    config_digest: digest, target_incarnation: role.incarnation, payload, ...over });
  let digest: string | null = null;
  const key = await send('CREATE_ISSUER_KEY', {}, { config_digest: null }) as { data: { token_key_spki_b64url: string } };
  const manifest = makeManifest({ run_id: runId, run_start_ms: Date.now() - 1000, token_key_spki_b64url: key.data.token_key_spki_b64url,
    snapshot_script_sha1: '1'.repeat(40), claim_script_sha1: '2'.repeat(40), inventory_total: count });
  await send('PREPARE_RUN', { manifest, proposed_config_digest: configurationDigest(manifest), role: 'issuer',
    role_config: { tls_cert_path: '/run/secrets/tls.crt', tls_key_path: '/run/secrets/tls.key' } }, { config_digest: null });
  digest = configurationDigest(manifest);
  const vouchers = Array.from({ length: count }, () => randomBytes(32));
  await send('PROVISION_VOUCHERS', { batch_id: 'd'.repeat(32), batch_index: 0, expected_total: count, final_batch: true, items: vouchers.map(voucherDigest) });
  await send('CHECK_READY');
  const enabled = await send('ENABLE') as { ok: boolean };
  if (!enabled.ok) throw new Error('rig issuer did not enable');
  const gateway = await startGateway(manifest, () => 0, gatewayTls);
  const proxy = await startProxy({ 'issuer.lab.test:443': role.address!.port, 'origin.lab.test:443': gateway.port });
  const made: LabClient[] = [];
  const clientVouchers = () => {
    const v = new ClientVouchers(count);
    v.provision({ batch_id: 'e'.repeat(32), batch_index: 0, expected_total: count, final_batch: true, items: vouchers.map((b) => encodeBase64Url(b, false)) });
    v.lock();
    return v;
  };
  return {
    pki, role, manifest, vouchers, gateway, proxy, clientVouchers,
    client: (over = {}) => {
      const c = new LabClient({ manifest, proxy: { host: '127.0.0.1', port: proxy.port }, caPem: pki.caPem, vouchers: clientVouchers(), now: () => manifest.run_start_ms + 1000, ...over });
      made.push(c); return c;
    },
    stop: async () => {
      for (const c of made) c.close();
      await role.handle({ version: 1, request_id: hex(randomBytes(16)), command: 'FENCE', run_id: null, config_digest: null, target_incarnation: null, payload: { reason: 'test-cleanup' } });
      gateway.server.closeAllConnections(); gateway.server.close(); proxy.server.close();
    },
  };
}
