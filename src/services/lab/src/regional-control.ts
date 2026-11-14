// Controller-only additions stay on a separate container-local socket.
import { createServer, connect } from 'node:net';
import { chmodSync } from 'node:fs';
import { canonicalJson, PROTOCOL } from '../../../contracts/lib/index.ts';
import { decodeCanonicalRegionalJson } from '../../../contracts/lib/regional-wire.ts';

export const REGIONAL_SOCKET = (process.env['PS024_CONTROL_SOCKET'] ?? PROTOCOL.control_socket) + '.regional';
const MAX = 65536;
type Json = Record<string, any>;

export function serveRegionalControl(handle: (command: Json) => Promise<Json>): Promise<void> {
  const server = createServer(socket => {
    let bytes = Buffer.alloc(0);
    let dispatched = false;
    socket.setTimeout(30000, () => socket.destroy());
    socket.on('error', () => socket.destroy());
    socket.on('data', chunk => {
      if (dispatched || bytes.length + chunk.length > MAX) { socket.destroy(); return; }
      bytes = Buffer.concat([bytes, chunk]);
      const end = bytes.indexOf(10);
      if (end < 0) return;
      if (end !== bytes.length - 1) { socket.destroy(); return; }
      dispatched = true;
      let command: Json;
      try {
        command = decodeCanonicalRegionalJson(bytes, true) as Json;
        if (!command || typeof command !== 'object' || Array.isArray(command)
          || !/^[0-9a-f]{32}$/.test(command.request_id)) throw Error();
      } catch { socket.destroy(); return; }
      void handle(command).then(data => {
        const reply = canonicalJson({ request_id: command.request_id, ok: true, data }) + '\n';
        if (Buffer.byteLength(reply) > MAX) throw Error();
        socket.end(reply);
      }).catch(() => socket.end(canonicalJson({ request_id: command.request_id, ok: false, code: 'regional-command-failed' }) + '\n'));
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(REGIONAL_SOCKET, () => {
      if (process.platform !== 'win32') chmodSync(REGIONAL_SOCKET, 0o600);
      resolve();
    });
  });
}

export async function regionalControlCall(command: Json): Promise<Json> {
  return new Promise((resolve, reject) => {
    const socket = connect(REGIONAL_SOCKET);
    let bytes = Buffer.alloc(0);
    let finished = false;
    const fail = () => { if (!finished) { finished = true; reject(Error('regional-control-unavailable')); } socket.destroy(); };
    socket.setTimeout(30000, fail);
    socket.on('error', fail);
    socket.once('connect', () => socket.write(canonicalJson(command) + '\n'));
    socket.on('data', chunk => {
      if (bytes.length + chunk.length > MAX) { fail(); return; }
      bytes = Buffer.concat([bytes, chunk]);
      if (!bytes.includes(10)) return;
      try {
        const reply = decodeCanonicalRegionalJson(bytes, true) as Json;
        if (reply.request_id !== command.request_id || typeof reply.ok !== 'boolean') throw Error();
        finished = true;
        socket.destroy();
        resolve(reply);
      } catch { fail(); }
    });
    socket.once('close', () => { if (!finished) fail(); });
  });
}

export function exactKeys(value: Json, keys: string[]): void {
  if (Object.keys(value).sort().join(',') !== keys.sort().join(',')) throw Error('regional-command-invalid');
}
