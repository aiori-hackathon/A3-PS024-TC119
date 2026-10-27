import { connect } from 'node:net';
import { PROTOCOL, validateControlRequest, validateControlResponse } from '../../../contracts/lib/index.ts';

// Run inside the role container. Keep stdin open for the owning controller's whole run.
const socket = connect(PROTOCOL.control_socket), pending = new Set<string>();
function fail(): never { socket.destroy(); process.stderr.write('control-helper-failed\n'); process.exit(1); }
socket.on('error', fail);
function lines(input: NodeJS.ReadableStream, consume: (line: Buffer) => void): void {
  let carry = Buffer.alloc(0);
  input.on('data', (chunk: Buffer) => {
    let offset = 0;
    while (offset < chunk.length) {
      const newline = chunk.indexOf(10, offset), end = newline < 0 ? chunk.length : newline;
      if (carry.length + end - offset > PROTOCOL.control_message_max_bytes) fail();
      const part = chunk.subarray(offset, end); carry = carry.length ? Buffer.concat([carry, part]) : Buffer.from(part);
      if (newline < 0) return;
      const line = carry; carry = Buffer.alloc(0); offset = newline + 1;
      try { consume(line); } catch { fail(); }
    }
  });
  input.once('end', () => { if (carry.length) fail(); });
}
let inputEnded = false;
socket.once('connect', () => {
  lines(process.stdin, line => {
    const request = validateControlRequest(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line)));
    const id = request['request_id'] as string;
    if (pending.has(id) || pending.size >= 9 || socket.writableLength + line.length + 1 > 9 * (PROTOCOL.control_message_max_bytes + 1)) fail();
    pending.add(id); socket.write(Buffer.concat([line, Buffer.from('\n')]));
  });
  process.stdin.once('end', () => { inputEnded = true; if (!pending.size) socket.end(); });
});
lines(socket, line => {
  const reply = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line)) as Record<string, unknown>;
  validateControlResponse(reply);
  if (!pending.delete(reply['request_id'] as string) || process.stdout.writableLength + line.length + 1 > 9 * (PROTOCOL.control_message_max_bytes + 1)) fail();
  process.stdout.write(Buffer.concat([line, Buffer.from('\n')]));
  if (inputEnded && !pending.size) socket.end();
});
socket.once('close', () => { if (pending.size) fail(); process.stdin.destroy(); });
process.on('uncaughtException', fail); process.on('unhandledRejection', fail);
