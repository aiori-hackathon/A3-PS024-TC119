// Issuer role process: private control listener plus the (initially closed) issuance service.
// Nothing is served until the controller drives PREPARE, provisioning, READY and ENABLE.
import { IssuerRole } from '../issuer/control.ts';
import { serveControl } from '../control-server.ts';
import { controlSocketPath, exitOnSignal, fenceRequest, listenConfig, readSecret } from './common.ts';

const role = new IssuerRole({ readSecret, listen: listenConfig() });
await serveControl(controlSocketPath(), (raw) => role.handle(raw));
exitOnSignal(() => role.handle(fenceRequest()));
