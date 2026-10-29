// Reset barrier for PARTIAL deployments only (development before the gateway runs in Compose). A full eight-role run
// must use Krish's ResetBarrier, which carries the complete obligations and tests; this class refuses to stand in for it.
// It honours the same rules for the roles it has: strong FENCED acknowledgement bound to the old run/config/incarnation,
// otherwise kill-and-confirm; origin counters are read from the settled REPORT only after its strong FENCE; the Redis
// discard is reachable only through a single-use receipt issued after EVERY participant has quiesced.
import { randomBytes } from 'node:crypto';
import { emergencyFence } from './envelope.ts';
import type { Json, ResetPort } from './ports.ts';
import type { DockerAdapters, Target } from './docker.ts';

export type PartialGeneration = { run_id: string; config_digest: string; redis_instance_id: string; participants: readonly Target[] };

export class PartialResetBarrier implements ResetPort {
  readonly #gen: PartialGeneration;
  readonly #adapters: DockerAdapters;
  readonly #deadlineMs: number;
  readonly #receipts = new WeakMap<object, { used: boolean }>();
  #fencing: Promise<object> | null = null;
  #state: 'prepared' | 'fenced' | 'blocked' | 'discarding' | 'discarded' | 'uncertain' = 'prepared';

  constructor(generation: PartialGeneration, adapters: DockerAdapters, deadlineMs = 10_000) {
    const roles = new Set(generation.participants.map((p) => p.role));
    if (roles.has('gateway') && generation.participants.length === 8) throw new Error('use-ResetBarrier-for-full-deployments');
    if (roles.size !== generation.participants.length) throw new Error('duplicate-role');
    this.#gen = generation; this.#adapters = adapters; this.#deadlineMs = deadlineMs;
  }

  async #stop(target: Target): Promise<void> {
    const request = emergencyFence('operator-stop');
    const strong = async (): Promise<boolean> => {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), this.#deadlineMs);
      try {
        const r = await this.#adapters.fence(target, request, ctl.signal) as Json;
        // Schema-valid is not enough: the reply must answer THIS request from THIS incarnation.
        return r['ok'] === true && r['result'] === 'FENCED' && r['state'] === 'FENCED' && r['request_id'] === request['request_id'] && r['incarnation'] === target.incarnation;
      } catch { return false; } finally { clearTimeout(timer); }
    };
    if (await strong()) {
      if (target.role === 'origin') {
        const ctl = new AbortController();
        const timer = setTimeout(() => ctl.abort(), this.#deadlineMs);
        try { await this.#adapters.reportOrigin(target, { version: 1, request_id: randomBytes(16).toString('hex'), command: 'REPORT', run_id: this.#gen.run_id, config_digest: this.#gen.config_digest, target_incarnation: target.incarnation, payload: {} }, ctl.signal); }
        catch { /* counts stay unavailable (null), never an invented zero */ } finally { clearTimeout(timer); }
      }
      return;
    }
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), this.#deadlineMs);
    try {
      const e = await this.#adapters.terminate(target, ctl.signal) as Record<string, unknown>;
      if (e['exited'] !== true || e['descendants_exited'] !== true || e['instance_id'] !== target.instance_id || e['role'] !== target.role || e['incarnation'] !== target.incarnation) throw new Error('evidence');
    } finally { clearTimeout(timer); }
  }

  fenceAll(): Promise<object> {
    if (this.#fencing) return this.#fencing;
    this.#fencing = Promise.allSettled(this.#gen.participants.map((t) => this.#stop(t))).then((results) => {
      if (results.some((r) => r.status === 'rejected')) { this.#state = 'blocked'; throw new Error('barrier-unconfirmed'); }
      this.#state = 'fenced';
      const receipt = Object.freeze({});
      this.#receipts.set(receipt, { used: false });
      return receipt;
    });
    this.#fencing.catch(() => undefined);
    return this.#fencing;
  }

  async discardOldRedis(receipt: unknown): Promise<void> {
    const proof = receipt && typeof receipt === 'object' ? this.#receipts.get(receipt) : undefined;
    if (!proof || proof.used || this.#state !== 'fenced') throw new Error('receipt-invalid');
    proof.used = true; this.#state = 'discarding'; // consumed before any await
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), this.#deadlineMs);
    try {
      const r = await this.#adapters.discardRedis(this.#gen.redis_instance_id, ctl.signal) as Record<string, unknown>;
      if (r['exited'] !== true || r['instance_id'] !== this.#gen.redis_instance_id) throw new Error('evidence');
      this.#state = 'discarded';
    } catch { this.#state = 'uncertain'; throw new Error('discard-unconfirmed'); } finally { clearTimeout(timer); }
  }
}
