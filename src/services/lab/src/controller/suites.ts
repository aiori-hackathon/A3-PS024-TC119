// Fixed suite definitions: which fresh runs to make and which named scenarios each one executes. A suite may contain
// several independent runs; each gets a new key, run ID and incarnations and its own evidence, and the preceding run is
// fully fenced (and its Redis discarded) before the next one is created. No scenario or run shape is caller-supplied.
import type { SuiteKind } from '../report/build.ts';
import type { ClientId } from './ports.ts';

const ALL: ClientId[] = ['A', 'B', 'C', 'D', 'E'];
export type Step = { scenario: string; clients: ClientId[] };
export type RunPlan = {
  name: string;
  clientProfile: 'demo' | 'security';
  gatewayProfile: 'B0' | 'B1';
  perClient: number;
  steps: Step[];
  /** Makes the first epoch boundary arrive soon after start (S09 only): run_start_ms = Redis TIME minus this. */
  epochOffsetMs?: number;
};
export type SuiteDefinition = { kind: SuiteKind; plans: RunPlan[] };

const one = (scenario: string, client: ClientId): Step => ({ scenario, clients: [client] });

export const SUITES: Record<string, SuiteDefinition> = {
  // Scenarios that need the gateway and the real issuer but no fault injection. S02 uses the demo client profile on purpose
  // (two vouchers per client, ordinary two-socket clients); S08 needs the bounded security profile (24 gateway sockets).
  'gateway-core': {
    kind: 'demo',
    plans: [
      { name: 'shared-egress', clientProfile: 'demo', gatewayProfile: 'B1', perClient: 2, steps: [{ scenario: 'shared-egress', clients: ALL }] },
      { name: 'core', clientProfile: 'security', gatewayProfile: 'B1', perClient: 10, steps: [
        one('healthy-flow', 'A'), one('voucher-policy', 'B'), one('wrong-context', 'C'), one('sequential-replay', 'D'), one('concurrent-replay', 'E'),
        one('malformed-token', 'A'), one('signature-and-key', 'B'), one('network-boundaries', 'C'),
      ] },
    ],
  },
};
