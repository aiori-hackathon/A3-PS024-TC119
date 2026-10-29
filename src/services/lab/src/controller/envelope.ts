import { randomBytes } from 'node:crypto';
import { hex } from '../../../../contracts/lib/index.ts';
import type { Json } from './ports.ts';

/** What the controller knows about one role after discovery and (later) PREPARE. */
export type Target = { incarnation: string; runId: string | null; digest: string | null };
export const newId = (): string => hex(randomBytes(16));

export function request(command: string, target: Target, payload: Json = {}, over: Json = {}): Json {
  return { version: 1, request_id: newId(), command, run_id: target.runId, config_digest: target.digest, target_incarnation: target.incarnation, payload, ...over };
}
export const discovery = (): Json =>
  ({ version: 1, request_id: newId(), command: 'STATUS', run_id: null, config_digest: null, target_incarnation: null, payload: {} });
export const emergencyFence = (reason: string): Json =>
  ({ version: 1, request_id: newId(), command: 'FENCE', run_id: null, config_digest: null, target_incarnation: null, payload: { reason } });
