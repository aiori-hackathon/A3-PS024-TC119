import { createServer, type Server, type Socket } from 'node:net';
import { chmod, lstat } from 'node:fs/promises';
import { dirname } from 'node:path';
import { PROTOCOL, validateControlRequest } from '../../../contracts/lib/index.ts';
import type { GatewaySupervisor } from './gateway-supervisor.ts';

/** Private same-UID Unix control only. A persistent owning helper supervises one immutable run. */
export class ControlServer {
  readonly #supervisor: GatewaySupervisor;
  readonly #server: Server;
  readonly #sockets = new Set<Socket>();
  #owner: Socket | null = null;
  #closed = false;
  constructor(supervisor: GatewaySupervisor) {
    this.#supervisor = supervisor;
    this.#server = createServer(socket => this.#accept(socket));
    this.#server.maxConnections = 4;
    this.#server.on('error', () => supervisor.fault('control-lost'));
  }
  async listen(path: string = PROTOCOL.control_socket): Promise<void> {
    if (process.platform === 'win32' || this.#closed) throw Error('private-control-unavailable');
    const directory = await lstat(dirname(path));
    if (!directory.isDirectory() || directory.isSymbolicLink() || directory.uid !== process.getuid!() || (directory.mode & 0o777) !== 0o700) throw Error('private-control-directory-invalid');
    // Caller sets umask077 before any listener. Never unlink a pre-existing socket or directory.
    await new Promise<void>((resolve, reject) => {
      this.#server.once('error', reject); this.#server.listen(path, () => { this.#server.off('error', reject); resolve(); });
    });
    await chmod(path, 0o600);
  }
  #accept(socket: Socket): void {
    if (this.#closed || this.#sockets.size >= 4) { socket.destroy(); return; }
    this.#sockets.add(socket); socket.on('error', () => socket.destroy());
    socket.once('close', () => {
      this.#sockets.delete(socket);
      if (this.#owner === socket && !this.#closed) this.#supervisor.fault('control-lost');
    });
    let carry = Buffer.alloc(0), pending = 0, fencing = false;
    const ids = new Set<string>();
    const dispatch = (line: Buffer) => {
      let request: Record<string, unknown>;
      try { request = validateControlRequest(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line))); }
      catch { socket.destroy(); return; }
      const command = request['command'];
      const id = request['request_id'] as string;
      if (ids.has(id)) { socket.destroy(); return; }
      if (command === 'FENCE' ? fencing : pending >= 8) { socket.destroy(); return; }
      if (!['STATUS', 'FENCE'].includes(command as string)) {
        if (!this.#owner && command === 'PREPARE_RUN' && request['target_incarnation'] === this.#supervisor.incarnation && !this.#supervisor.status.run_closed) this.#owner = socket;
        if (this.#owner !== socket) { socket.destroy(); return; }
      }
      ids.add(id); if (command === 'FENCE') fencing = true; else pending++;
      this.#supervisor.handle(request).then(response => {
        if (socket.destroyed) return;
        const bytes = Buffer.from(JSON.stringify(response) + '\n');
        if (bytes.length > PROTOCOL.control_message_max_bytes + 1 || socket.writableLength + bytes.length > 9 * (PROTOCOL.control_message_max_bytes + 1)) { socket.destroy(); return; }
        socket.write(bytes);
      }, () => { socket.destroy(); }).finally(() => { ids.delete(id); if (command === 'FENCE') fencing = false; else pending--; });
    };
    socket.on('data', (chunk: Buffer) => {
      let offset = 0;
      while (offset < chunk.length && !socket.destroyed) {
        const newline = chunk.indexOf(10, offset), end = newline < 0 ? chunk.length : newline;
        if (carry.length + end - offset > PROTOCOL.control_message_max_bytes) { socket.destroy(); return; }
        const part = chunk.subarray(offset, end);
        carry = carry.length ? Buffer.concat([carry, part]) : Buffer.from(part);
        if (newline < 0) return;
        const line = carry; carry = Buffer.alloc(0); offset = newline + 1; dispatch(line);
      }
    });
  }
  async close(): Promise<void> {
    this.#closed = true; for (const socket of this.#sockets) socket.destroy();
    if (this.#server.listening) await new Promise<void>((resolve, reject) => this.#server.close(error => error ? reject(Error('control-close-failed')) : resolve()));
  }
}
