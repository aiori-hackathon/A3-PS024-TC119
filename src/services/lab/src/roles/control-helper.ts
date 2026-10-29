// Container-local control helper: the controller runs it inside a role container and keeps its stdin open.
// stdin carries one validated request per line (credentials never touch argv or logs); stdout carries validated
// replies. It holds no state, echoes nothing it was given, and exits non-zero with a fixed message on any violation.
import { connect } from 'node:net';
import { PROTOCOL, validateControlRequest, validateControlResponse } from '../../../../contracts/lib/index.ts';
import { controlSocketPath } from './common.ts';

const MAX = PROTOCOL.control_message_max_bytes;
const MAX_PENDING = 9; // eight ordinary requests plus the reserved FENCE path
const socket = connect(controlSocketPath());
const pending = new Set<string>();
let inputEnded = false;

function fail(): never {
  socket.destroy();
  process.stderr.write('control-helper-failed\n');
  process.exit(1);
}
function lines(input: NodeJS.ReadableStream, onLine: (line: Buffer) => void): void {
  let carry = Buffer.alloc(0);
  input.on('data', (chunk: Buffer) => {
    let offset = 0;
    while (offset < chunk.length) {
      const nl = chunk.indexOf(10, offset);
      const end = nl < 0 ? chunk.length : nl;
      if (carry.length + end - offset > MAX) fail();
      carry = Buffer.concat([carry, chunk.subarray(offset, end)]);
      if (nl < 0) return;
      const line = carry; carry = Buffer.alloc(0); offset = nl + 1;
      try { onLine(line); } catch { fail(); }
    }
  });
  input.once('end', () => { if (carry.length) fail(); });
}
const decode = (line: Buffer): unknown => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line));

socket.on('error', fail);
socket.once('connect', () => {
  lines(process.stdin, (line) => {
    const request = validateControlRequest(decode(line));
    const id = request['request_id'] as string;
    if (pending.has(id) || pending.size >= MAX_PENDING) fail();
    pending.add(id);
    socket.write(Buffer.concat([line, Buffer.from('\n')]));
  });
  process.stdin.once('end', () => { inputEnded = true; if (!pending.size) socket.end(); });
});
lines(socket, (line) => {
  const reply = decode(line) as Record<string, unknown>;
  validateControlResponse(reply);
  if (!pending.delete(reply['request_id'] as string)) fail(); // unsolicited or duplicate reply
  process.stdout.write(Buffer.concat([line, Buffer.from('\n')]));
  if (inputEnded && !pending.size) socket.end();
});
socket.once('close', () => { if (pending.size) fail(); process.stdin.destroy(); });
process.on('uncaughtException', fail);
process.on('unhandledRejection', fail);
