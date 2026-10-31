// Fixed suite definitions: which fresh runs to make and which named scenarios each one executes. A suite may contain
// several independent runs; each gets a new key, run ID and incarnations and its own evidence, and the preceding run is
// fully fenced (and its Redis discarded) before the next one is created. No scenario or run shape is caller-supplied.
import type { SuiteKind } from '../report/build.ts';
import type { ClientId } from './ports.ts';

const ALL: ClientId[] = ['A', 'B', 'C', 'D', 'E'];
export type Step =
  | { scenario: string; clients: ClientId[] }      // runs inside client container(s) via RUN_SCENARIO
  | { orchestrated: string }                       // runs in the controller with the harness / fault port (e.g. 'redis-failure:script-flush')
  | { capture: 'old-run' };                        // hidden half of S13: quarantine one spent and one unused credential across the reset
export type RunPlan = {
  name: string;
  clientProfile: 'demo' | 'security';
  gatewayProfile: 'B0' | 'B1';
  perClient: number;
  /** Extra vouchers kept in controller memory for the security harness. */
  harnessVouchers?: number;
  steps: Step[];
  /** Makes the first epoch boundary arrive soon after start (S09 only): run_start_ms = Redis TIME minus this. */
  epochOffsetMs?: number;
};
export type SuiteDefinition = { kind: SuiteKind; plans: RunPlan[] };

const one = (scenario: string, client: ClientId): Step => ({ scenario, clients: [client] });
const sharedEgress: RunPlan = { name: 'shared-egress', clientProfile: 'demo', gatewayProfile: 'B1', perClient: 2, steps: [{ scenario: 'shared-egress', clients: ALL }] };

export const SUITES: Record<string, SuiteDefinition> = {
  // Scenarios that need the gateway and the real issuer but no fault injection. S02 uses the demo client profile on purpose
  // (two vouchers per client, ordinary two-socket clients); S08 needs the bounded security profile (24 gateway sockets).
  'gateway-core': {
    kind: 'demo',
    plans: [
      sharedEgress,
      { name: 'core', clientProfile: 'security', gatewayProfile: 'B1', perClient: 10, steps: [
        one('healthy-flow', 'A'), one('voucher-policy', 'B'), one('wrong-context', 'C'), one('sequential-replay', 'D'), one('concurrent-replay', 'E'),
        one('malformed-token', 'A'), one('signature-and-key', 'B'), one('network-boundaries', 'C'),
      ] },
    ],
  },
  // Real replay-store faults, one per fresh run (each fault closes its run), plus the recorded-highwater regression.
  'redis-faults': {
    kind: 'security',
    plans: ['redis-failure:script-flush', 'redis-failure:clock-delete', 'redis-failure:policy-corrupt', 'redis-failure:redis-stop', 'clock-rollback:clock-regress'].map((key) => ({
      name: key.replace(':', '-'), clientProfile: 'security' as const, gatewayProfile: 'B1' as const, perClient: 2, harnessVouchers: 4, steps: [{ orchestrated: key }],
    })),
  },
  'redis-one': {
    kind: 'security',
    plans: [{ name: 'redis-failure-script-flush', clientProfile: 'security', gatewayProfile: 'B1', perClient: 2, harnessVouchers: 4, steps: [{ orchestrated: 'redis-failure:script-flush' }] }],
  },
  // S15 needs real traffic first, so the audit runs after a healthy flow in the same live generation.
  retention: {
    kind: 'security',
    plans: [{ name: 'retention', clientProfile: 'security', gatewayProfile: 'B1', perClient: 2, steps: [one('healthy-flow', 'A'), { orchestrated: 'retention-audit' }] }],
  },
  // S09: run_start_ms is moved back so the first boundary arrives ~80 s after the clients start; setup leaves a margin.
  'epoch-boundary': {
    kind: 'security',
    plans: [{ name: 'epoch-boundary', clientProfile: 'security', gatewayProfile: 'B1', perClient: 4, epochOffsetMs: 600_000 - 80_000, steps: [one('epoch-boundary', 'A')] }],
  },
  // S10: all five clients burst and stall together so the load arrives at the gateway at once.
  'admission-limits': {
    kind: 'security',
    plans: [{ name: 'admission-limits', clientProfile: 'security', gatewayProfile: 'B1', perClient: 24, steps: [{ scenario: 'admission-limits', clients: ALL }] }],
  },
  'upstream': {
    kind: 'security',
    plans: [{ name: 'upstream-failure', clientProfile: 'security', gatewayProfile: 'B1', perClient: 2, harnessVouchers: 4, steps: [{ orchestrated: 'upstream-failure' }] }],
  },
  // The demonstration: every scenario the frozen protocol requires for a complete demo, each against the real deployment.
  demo: {
    kind: 'demo',
    plans: [
      sharedEgress,
      { name: 'core', clientProfile: 'security', gatewayProfile: 'B1', perClient: 10, harnessVouchers: 4, steps: [
        one('healthy-flow', 'A'), one('wrong-context', 'C'), one('sequential-replay', 'D'), one('concurrent-replay', 'E'), { orchestrated: 'stolen-unused-token' },
      ] },
      { name: 'reset-old-generation', clientProfile: 'security', gatewayProfile: 'B1', perClient: 2, harnessVouchers: 4, steps: [{ capture: 'old-run' }] },
      { name: 'reset-new-generation', clientProfile: 'security', gatewayProfile: 'B1', perClient: 2, harnessVouchers: 4, steps: [{ orchestrated: 'restart-and-reset' }] },
      { name: 'redis-fault', clientProfile: 'security', gatewayProfile: 'B1', perClient: 2, harnessVouchers: 4, steps: [{ orchestrated: 'redis-failure:script-flush' }] },
    ],
  },
};
