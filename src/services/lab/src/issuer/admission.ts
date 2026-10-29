// Bounded FIFO admission for signing: N active permits, bounded queue, bounded monotonic wait.
// A permit is held until the guarded operation actually settles.
export class AdmissionGate {
  readonly #active: number;
  readonly #depth: number;
  readonly #waitMs: number;
  #running = 0;
  readonly #queue: { grant: () => void; cancel: () => void; timer: NodeJS.Timeout }[] = [];

  constructor(active: number, queueDepth: number, queueWaitMs: number) {
    this.#active = active; this.#depth = queueDepth; this.#waitMs = queueWaitMs;
  }
  get running(): number { return this.#running; }
  get queued(): number { return this.#queue.length; }

  /** Resolves to a release function, or null when the queue is full or the wait expired. */
  acquire(): Promise<(() => void) | null> {
    if (this.#running < this.#active) { this.#running += 1; return Promise.resolve(this.#release()); }
    if (this.#queue.length >= this.#depth) return Promise.resolve(null);
    return new Promise((resolve) => {
      const entry = {
        grant: () => { clearTimeout(entry.timer); this.#running += 1; resolve(this.#release()); },
        cancel: () => { clearTimeout(entry.timer); resolve(null); },
        timer: setTimeout(() => {
          const i = this.#queue.indexOf(entry);
          if (i >= 0) this.#queue.splice(i, 1);
          resolve(null);
        }, this.#waitMs),
      };
      this.#queue.push(entry);
    });
  }
  #release(): () => void {
    let done = false;
    return () => {
      if (done) return;
      done = true; this.#running -= 1;
      this.#queue.shift()?.grant();
    };
  }
  /** Drops all waiters (fence); active permits still settle on their own. */
  cancelQueued(): void {
    for (const e of this.#queue.splice(0)) e.cancel();
  }
}
