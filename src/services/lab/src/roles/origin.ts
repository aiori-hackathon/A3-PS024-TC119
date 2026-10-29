// Private protected origin process. Plain HTTP on the gateway_origin network only; it dials nothing.
import { OriginRole } from '../origin/control.ts';
import { serveControl } from '../control-server.ts';
import { controlSocketPath, exitOnSignal, fenceRequest, listenConfig } from './common.ts';

const role = new OriginRole({ listen: { host: listenConfig().host, port: Number(process.env['PS024_LISTEN_PORT'] ?? 8080) } });
await serveControl(controlSocketPath(), (raw) => role.handle(raw));
exitOnSignal(() => role.handle(fenceRequest()));
