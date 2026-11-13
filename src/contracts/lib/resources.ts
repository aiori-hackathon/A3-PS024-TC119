import { performance } from 'node:perf_hooks';
export type ResourceScope = 'gateway-worker' | 'gateway-supervisor' | 'controller' | 'issuer' | 'origin' | 'client';
export type ResourceMeasurement = {
  scope: ResourceScope; worker_index: number | null; elapsed_ms: number;
  cpu_user_us: number; cpu_system_us: number; peak_rss_bytes: number;
  memory_scope: 'process-lifetime-highwater';
};
/** CPU delta since construction; RSS highwater is explicitly the entire process lifetime, not a container peak. */
export class ResourceProbe {
  readonly #cpu = process.cpuUsage();
  readonly #start = performance.now();
  readonly #scope: ResourceScope;
  constructor(scope: ResourceScope) { this.#scope = scope; }
  summary(worker_index: number | null = null): ResourceMeasurement {
    const cpu = process.cpuUsage(this.#cpu);
    return { scope: this.#scope, worker_index, elapsed_ms: Math.round((performance.now() - this.#start) * 1000) / 1000,
      cpu_user_us: cpu.user, cpu_system_us: cpu.system, peak_rss_bytes: process.resourceUsage().maxRSS * 1024,
      memory_scope: 'process-lifetime-highwater' };
  }
}
export type RpcOutcome = { operation: 'snapshot' | 'claim'; failures: number; timeouts: number; uncertain: number };
