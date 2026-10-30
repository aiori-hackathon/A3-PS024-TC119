// Identity-bound cleanup outside any LabRun. A run can fail before it has a complete, immutable snapshot (no manifest yet,
// the gateway not yet discovered), and the previous generation may still be alive when a new controller starts. Neither case
// can use the full reset barrier, which needs every incarnation and the manifest, and neither may invent those values.
// This scope instead works from what is certain: the immutable container IDs that were actually created or found.
// Rules: strong FENCE is attempted where a link exists, but only kill-and-CONFIRM (by inspecting the exact ID) counts; the
// old Redis is removed only after EVERY role is confirmed gone; an unconfirmed exit means the scope reports failure and the
// caller keeps the project lock. A stale lock, or a newly acquired one, is never evidence that anything stopped.
import { emergencyFence } from './envelope.ts';
import type { DockerAdapters } from './docker.ts';
import type { ResetPort, RoleLink, RoleName } from './ports.ts';

export type Created = { name: string; container_id: string; role?: RoleName; link?: RoleLink | undefined };
const ZERO_INCARNATION = '0'.repeat(32);

export class CleanupScope {
  readonly #roles = new Map<string, Created>();
  #redisId: string | null = null;
  recordRole(c: Created): void { this.#roles.set(c.container_id, c); }
  recordLink(containerId: string, link: RoleLink): void { const c = this.#roles.get(containerId); if (c) c.link = link; }
  recordRedis(containerId: string): void { this.#redisId = containerId; }
  get redisId(): string | null { return this.#redisId; }
  get roles(): Created[] { return [...this.#roles.values()]; }
}

const controller = (ms: number) => { const c = new AbortController(); const t = setTimeout(() => c.abort(), ms); t.unref(); return { signal: c.signal, done: () => clearTimeout(t) }; };

/** Stops every recorded role. Resolves true only if every one is confirmed gone; never touches Redis. */
export async function stopRoles(scope: CleanupScope, adapters: Pick<DockerAdapters, 'terminate'>, deadlineMs = 12_000): Promise<boolean> {
  const results = await Promise.allSettled(scope.roles.map(async (c) => {
    if (c.link) { try { await c.link.send(emergencyFence('operator-stop'), 4000); } catch { /* best effort: only confirmed exit counts */ } }
    const t = controller(deadlineMs);
    try { await adapters.terminate({ role: c.role ?? 'issuer', incarnation: ZERO_INCARNATION, instance_id: c.container_id }, t.signal); } finally { t.done(); }
  }));
  return results.every((r) => r.status === 'fulfilled');
}

/** Removes the recorded Redis container; true only if the daemon states it no longer exists. Call only after stopRoles() === true. */
export async function discardRedis(scope: CleanupScope, adapters: Pick<DockerAdapters, 'discardRedis'>, deadlineMs = 12_000): Promise<boolean> {
  if (!scope.redisId) return true;
  const t = controller(deadlineMs);
  try { await adapters.discardRedis(scope.redisId, t.signal); return true; } catch { return false; } finally { t.done(); }
}

/** ResetPort for the cases the full barrier cannot serve. A single-use receipt separates "roles gone" from "Redis discarded". */
export class ScopeBarrier implements ResetPort {
  readonly #scope: CleanupScope;
  readonly #adapters: Pick<DockerAdapters, 'terminate' | 'discardRedis'>;
  readonly #receipts = new WeakMap<object, { used: boolean }>();
  #fencing: Promise<object> | null = null;
  constructor(scope: CleanupScope, adapters: Pick<DockerAdapters, 'terminate' | 'discardRedis'>) { this.#scope = scope; this.#adapters = adapters; }
  fenceAll(): Promise<object> {
    this.#fencing ??= (async () => {
      if (!(await stopRoles(this.#scope, this.#adapters))) throw new Error('scope-unconfirmed');
      const receipt = Object.freeze({}); this.#receipts.set(receipt, { used: false }); return receipt;
    })();
    this.#fencing.catch(() => undefined);
    return this.#fencing;
  }
  async discardOldRedis(receipt: unknown): Promise<void> {
    const proof = receipt && typeof receipt === 'object' ? this.#receipts.get(receipt) : undefined;
    if (!proof || proof.used) throw new Error('receipt-invalid');
    proof.used = true;
    if (!(await discardRedis(this.#scope, this.#adapters))) throw new Error('discard-unconfirmed');
  }
}
