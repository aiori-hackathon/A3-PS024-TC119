// Issuer role process: private control listener plus the (initially closed) issuance service.
// Nothing is served until the controller drives PREPARE, provisioning, READY and ENABLE.
import { IssuerRole } from '../issuer/control.ts';
import { serveControl } from '../control-server.ts';
import { controlSocketPath, exitOnSignal, fenceRequest, listenConfig, readSecret } from './common.ts';
import { WorkerSigner } from '../issuer/worker-signer.ts';
import { serveRegionalControl, exactKeys } from '../regional-control.ts';

const role = new IssuerRole({ readSecret, listen: listenConfig(),
  createSigner: (name, failed) => WorkerSigner.create(new URL(import.meta.url.endsWith('.ts')
    ? '../issuer/signing-worker.ts' : './signing-worker.mjs', import.meta.url), name, failed) });
await serveControl(controlSocketPath(), (raw) => role.handle(raw));
await serveRegionalControl(async command => {
  exactKeys(command, ['operation', 'request_id', 'config']);
  if (command.operation !== 'install') throw Error();
  const config = command.config;
  if (config.arc) {
    if (!/^[0-9a-f]{64}$/.test(config.arc.issueKey)) throw Error();
    config.arc.issueKey = Uint8Array.from(Buffer.from(config.arc.issueKey, 'hex'));
  }
  await role.installRegional(config);
  return { status: 'installed' };
});
exitOnSignal(() => role.handle(fenceRequest()));
