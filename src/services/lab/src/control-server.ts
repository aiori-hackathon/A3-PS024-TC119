// Newline-delimited JSON control listener on a private local socket (plan section 5.1).
// Role-agnostic: it frames, bounds and dispatches; the role decides meaning. Requests are dispatched without
// waiting for earlier ones and replies are correlated by request_id, so a stalled command cannot block FENCE.
import { createServer, type Server, type Socket } from 'node:net';
import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { PROTOCOL } from '../../../contracts/lib/index.ts';

export type ControlHandler = (raw: unknown) => Promise<Record<string, unknown>>;
const MAX_LINE = PROTOCOL.control_message_max_bytes;

export function serveControl(path: string, handle: ControlHandler, options: { maxPending?: number } = {}): Promise<Server> {
  const maxPending = options.maxPending ?? 8;
  const server = createServer((socket: Socket) => {
    let buffered = '';
    let pending = 0;
    socket.setEncoding('utf8');
    socket.on('error', () => socket.destroy());
    socket.on('data', (chunk: string) => {
      buffered += chunk;
      let at: number;
      while ((at = buffered.indexOf('\n')) >= 0) {
        const line = buffered.slice(0, at); buffered = buffered.slice(at + 1);
        if (Buffer.byteLength(line, 'utf8') > MAX_LINE) { socket.destroy(); return; }
        let raw: unknown = line;
        try { raw = JSON.parse(line); } catch { /* the role rejects a non-object as a fixed error */ }
        const urgent = typeof raw === 'object' && raw !== null && ['FENCE', 'STATUS'].includes((raw as { command?: string }).command ?? '');
        // At most eight ordinary requests in flight per connection; FENCE and STATUS keep a reserved path.
        if (pending >= maxPending && !urgent) { socket.destroy(); return; }
        pending += 1;
        void handle(raw).then((reply) => { if (socket.writable) socket.write(JSON.stringify(reply) + '\n'); })
          .catch(() => socket.destroy())
          .finally(() => { pending -= 1; });
      }
      if (Buffer.byteLength(buffered, 'utf8') > MAX_LINE) socket.destroy(); // unterminated oversize line
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    if (process.platform !== 'win32') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    server.listen(path, () => {
      if (process.platform !== 'win32') chmodSync(path, 0o600);
      resolve(server);
    });
  });
}
