// Interfaces the controller depends on. Real implementations: docker.ts (links, container evidence) and Krish's
// ResetBarrier / Redis bootstrap; tests use in-process roles and fakes. Nothing here carries a secret in a type that
// could be logged: credentials are passed by value into the one function that needs them.
import type { Manifest } from '../../../../contracts/lib/index.ts';

export type Json = Record<string, any>;
export const CLIENT_IDS = ['A', 'B', 'C', 'D', 'E'] as const;
export type ClientId = (typeof CLIENT_IDS)[number];
export type RoleName = 'gateway' | 'issuer' | 'origin' | `client-${ClientId}`;

/** A persistent private control channel to one role. Replies are correlated by request_id, never by order. */
export interface RoleLink {
  readonly role: RoleName;
  send(request: Json, timeoutMs?: number): Promise<Json>;
  close(): void;
}

export type GatewayCredentials = Readonly<{ username: string; password: string }>;

/** Replay-store bootstrap (Krish's schema and scripts, consumed unchanged). */
export interface RedisPort {
  /** Loads the exact scripts into the fenced store and reads its clock. Called once, before the manifest exists. */
  prepare(runId: string): Promise<{ run_start_ms: number; snapshot_script_sha1: string; claim_script_sha1: string }>;
  /** Installs immutable policy/clock for the accepted manifest and sets minimal ACLs. Returns the gateway account. */
  install(manifest: Manifest, configDigest: string): Promise<GatewayCredentials>;
}

/** Delivers the gateway's startup configuration (credentials over private stdin, never argv/env/logs). */
export interface GatewayLauncher {
  launch(input: { redis: GatewayCredentials }): Promise<void>;
}

/** Strong reset barrier. The production implementation is Krish's ResetBarrier driven by this controller's adapters. */
export interface ResetPort {
  fenceAll(): Promise<unknown>;
  discardOldRedis(receipt: unknown): Promise<void>;
}

export type OriginCounts = Readonly<{ protected_requests_received: number; generation_mismatches: number; resources_served: number }>;
