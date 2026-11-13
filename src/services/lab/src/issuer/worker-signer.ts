import { Worker } from 'node:worker_threads';
import { PROTOCOL } from '../../../../contracts/lib/index.ts';
import type { IssuerSigner } from '../protocol.ts';

type Pending = {
  resolve: (wire: Uint8Array<ArrayBuffer>) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
};

/** A bounded private bridge. The RSA private key is created and retained in the worker. */
export class WorkerSigner implements IssuerSigner {
  readonly publicKeySpki: Uint8Array<ArrayBuffer>;
  readonly #worker: Worker;
  readonly #failed: () => void;
  readonly #pending = new Map<number, Pending>();
  #sequence = 0;
  #closed = false;
  #termination: Promise<void> | null = null;

  private constructor(worker: Worker, spki: Uint8Array, failed: () => void) {
    this.#worker = worker;
    this.publicKeySpki = Uint8Array.from(spki);
    this.#failed = failed;
    worker.on('error', () => this.#fail());
    worker.on('exit', () => this.#fail());
    worker.on('message', (message: unknown) => this.#receive(message));
  }

  static async create(url: URL, issuerName: string, failed: () => void): Promise<WorkerSigner> {
    const worker = new Worker(url, { workerData: { issuerName } });
    try {
      const spki = await new Promise<Uint8Array>((resolve, reject) => {
        const done = () => { clearTimeout(timer); worker.off('message', ready); worker.off('error', unavailable); worker.off('exit', unavailable); };
        const unavailable = () => { done(); reject(new Error('signer-unavailable')); };
        const ready = (message: { kind?: unknown; spki?: unknown }) => {
          if (message?.kind !== 'ready' || !(message.spki instanceof Uint8Array) || message.spki.length > 1024 || message.spki.length < 256) return unavailable();
          done(); resolve(message.spki);
        };
        const timer = setTimeout(unavailable, 30_000);
        worker.once('message', ready);
        worker.once('error', unavailable);
        worker.once('exit', unavailable);
      });
      return new WorkerSigner(worker, spki, failed);
    } catch {
      await worker.terminate();
      throw new Error('signer-unavailable');
    }
  }

  sign(wire: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
    if (this.#closed || wire.length !== PROTOCOL.request_bytes || this.#pending.size >= PROTOCOL.issuer_limits.active_signings) {
      return Promise.reject(new Error('signer-unavailable'));
    }
    const id = ++this.#sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.#fail(), 10_000);
      this.#pending.set(id, { resolve, reject, timer });
      try { this.#worker.postMessage({ id, wire }); } catch { this.#fail(); }
    });
  }

  #receive(message: unknown): void {
    if (this.#closed) return;
    const m = message as { kind?: unknown; id?: number; wire?: unknown };
    const pending = this.#pending.get(m?.id as number);
    if (!pending || (m.kind !== 'signed' && m.kind !== 'rejected')) return this.#fail();
    if (m.kind === 'signed' && (!(m.wire instanceof Uint8Array) || m.wire.length !== PROTOCOL.response_bytes)) return this.#fail();
    clearTimeout(pending.timer);
    this.#pending.delete(m.id!);
    if (m.kind === 'signed') pending.resolve(Uint8Array.from(m.wire as Uint8Array));
    else pending.reject(new Error('signing-rejected'));
  }

  #fail(): void {
    if (this.#closed) return;
    void this.close();
    this.#failed();
  }

  close(): Promise<void> {
    if (this.#termination) return this.#termination;
    this.#closed = true;
    for (const pending of this.#pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error('signer-unavailable'));
    }
    this.#pending.clear();
    this.#termination = this.#worker.terminate().then(() => undefined);
    return this.#termination;
  }
}
