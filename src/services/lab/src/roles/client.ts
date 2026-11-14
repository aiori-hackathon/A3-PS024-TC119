// Client role process. A client opens no listener except its private control socket; all traffic is outbound
// through the lab proxy once the controller enables it.
import { ClientRole } from '../client/control.ts';
import { serveControl } from '../control-server.ts';
import { controlSocketPath, exitOnSignal, fenceRequest, readSecret } from './common.ts';
import { serveRegionalControl, exactKeys } from '../regional-control.ts';

const role = new ClientRole({ readSecret });
await serveControl(controlSocketPath(), (raw) => role.handle(raw));
await serveRegionalControl(async command => {
  if (command.operation === 'install') {
    exactKeys(command, ['operation', 'request_id', 'config']);
    await role.installRegional(command.config);
    return { status: 'installed' };
  }
  if (command.operation === 'status') {
    exactKeys(command, ['operation', 'request_id']);
    return role.regionalStatus();
  }
  exactKeys(command, ['operation', 'request_id', 'action', 'count']);
  if (command.operation !== 'action' || !['acquire', 'access', 'attack', 'copy', 'race', 'abuse'].includes(command.action)
    || !Number.isSafeInteger(command.count) || command.count < 1 || command.count > 26) throw Error();
  return role.regionalAction(command.action, command.count);
});
exitOnSignal(() => role.handle(fenceRequest()));
