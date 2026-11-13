import { parentPort, workerData } from 'node:worker_threads';
if (workerData.issuerName === 'startup-exit') process.exit(1);
parentPort!.postMessage({ kind: 'ready', spki: new Uint8Array(294) });
parentPort!.once('message', (m) => {
  if (workerData.issuerName === 'invalid-response') parentPort!.postMessage({ kind: 'signed', id: m.id, wire: new Uint8Array(1) });
  else process.exit(1);
});
