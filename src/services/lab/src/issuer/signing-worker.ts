// The pinned library's RSA private operation is synchronous JavaScript. Keep it off the
// issuer's HTTP/control thread so signing cannot delay lease checks or heartbeats.
import { parentPort, workerData } from 'node:worker_threads';
import { LabIssuer } from '../protocol.ts';
import { PROTOCOL } from '../../../../contracts/lib/index.ts';

if (!parentPort || typeof workerData?.issuerName !== 'string') throw new Error('signer-startup');
const port = parentPort;
const issuer = await LabIssuer.generate(workerData.issuerName);
port.postMessage({ kind: 'ready', spki: issuer.publicKeySpki });
port.on('message', async (message: unknown) => {
  const m = message as { id?: unknown; wire?: unknown };
  if (!Number.isSafeInteger(m?.id) || !(m.wire instanceof Uint8Array) || m.wire.length !== PROTOCOL.request_bytes) {
    process.exit(1);
  }
  const wire = m.wire as Uint8Array;
  try {
    const response = await issuer.sign(wire);
    port.postMessage({ kind: 'signed', id: m.id, wire: response });
    response.fill(0);
  } catch {
    port.postMessage({ kind: 'rejected', id: m.id });
  } finally {
    wire.fill(0);
  }
});
