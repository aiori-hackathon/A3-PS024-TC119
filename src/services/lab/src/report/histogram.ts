// Fixed-bucket latency histograms for the report's `measurements`. Only aggregates are kept: a count per bucket, never an
// individual timing, token or request. Bucket i holds values <= bound[i] (and > bound[i-1]); the last bucket is the overflow.
// A quantile is reported as the UPPER BOUND of the bucket it falls in (a conservative estimate, not an interpolation), and as
// null when it falls in the overflow bucket or when there are no samples.
import { PROTOCOL } from '../../../../contracts/lib/index.ts';

export type MetricName = 'issuance_http_ms' | 'token_acquisition_ms' | 'verification_ms' | 'snapshot_rpc_ms' | 'claim_rpc_ms' | 'queue_wait_ms' | 'authorization_ms' | 'protected_response_ms';
export type Measurement = {
  metric: MetricName; count: number; failures: number; elapsed_ms: number;
  p50_ms: number | null; p95_ms: number | null; p99_ms: number | null; histogram_counts: number[];
};
export const BOUNDS: readonly number[] = PROTOCOL.histogram_bounds_ms;
export const BUCKETS = BOUNDS.length + 1;

export function bucketOf(ms: number): number {
  if (!Number.isFinite(ms) || ms < 0) return BUCKETS - 1;
  for (let i = 0; i < BOUNDS.length; i++) if (ms <= BOUNDS[i]!) return i;
  return BUCKETS - 1;
}

export function quantile(counts: readonly number[], q: number): number | null {
  const total = counts.reduce((a, b) => a + b, 0);
  if (total === 0) return null;
  const rank = Math.ceil(q * total);
  let seen = 0;
  for (let i = 0; i < counts.length; i++) {
    seen += counts[i]!;
    if (seen >= rank) return i < BOUNDS.length ? BOUNDS[i]! : null;
  }
  return null;
}

export function summarize(metric: MetricName, counts: readonly number[], failures: number, elapsedMs: number): Measurement {
  const histogram_counts = [...counts];
  return {
    metric, count: histogram_counts.reduce((a, b) => a + b, 0), failures, elapsed_ms: Math.round(elapsedMs * 1000) / 1000,
    p50_ms: quantile(histogram_counts, 0.5), p95_ms: quantile(histogram_counts, 0.95), p99_ms: quantile(histogram_counts, 0.99), histogram_counts,
  };
}

/** Accumulates samples for one metric in memory. */
export class Histogram {
  readonly #counts = new Array<number>(BUCKETS).fill(0);
  #failures = 0;
  add(ms: number): void { this.#counts[bucketOf(ms)]!++; }
  fail(): void { this.#failures++; }
  summary(metric: MetricName, elapsedMs: number): Measurement { return summarize(metric, this.#counts, this.#failures, elapsedMs); }
}

/** Merges the per-client measurements of one metric: counts and failures add, elapsed is the longest, quantiles are recomputed. */
export function mergeMeasurements(groups: readonly (readonly Measurement[])[]): Measurement[] {
  const by = new Map<MetricName, { counts: number[]; failures: number; elapsed: number }>();
  for (const group of groups) for (const m of group) {
    const cur = by.get(m.metric) ?? { counts: new Array<number>(BUCKETS).fill(0), failures: 0, elapsed: 0 };
    m.histogram_counts.forEach((c, i) => { cur.counts[i]! += c; });
    cur.failures += m.failures; cur.elapsed = Math.max(cur.elapsed, m.elapsed_ms);
    by.set(m.metric, cur);
  }
  return [...by].map(([metric, v]) => summarize(metric, v.counts, v.failures, v.elapsed));
}
