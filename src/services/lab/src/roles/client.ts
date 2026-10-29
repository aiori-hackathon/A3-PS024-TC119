// Client role process. A client opens no listener except its private control socket; all traffic is outbound
// through the lab proxy once the controller enables it.
import { ClientRole } from '../client/control.ts';
import { serveControl } from '../control-server.ts';
import { controlSocketPath, exitOnSignal, fenceRequest, readSecret } from './common.ts';

const role = new ClientRole({ readSecret });
await serveControl(controlSocketPath(), (raw) => role.handle(raw));
exitOnSignal(() => role.handle(fenceRequest()));
