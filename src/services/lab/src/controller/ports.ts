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

/**
 * Starts the gateway's serving entry point with its private startup input (listen_host, TLS key/cert, Redis account) over
 * stdin, never argv/env/labels/logs, and returns a control link to the process that is now serving. The gateway's control
 * socket does not exist until that input has been validated, so discovery of the gateway can only follow this call.
 */
export interface GatewayLauncher {
  launch(input: { redis: GatewayCredentials }): Promise<RoleLink>;
}

/** Strong reset barrier. The production implementation is Krish's ResetBarrier driven by this controller's adapters. */
export interface ResetPort {
  fenceAll(): Promise<unknown>;
  discardOldRedis(receipt: unknown): Promise<void>;
}

/**
 * The controller's own security harness: one-shot processes run INSIDE a client container (so they use the real proxy path, CA
 * and network position) that issue or present tokens for the theft, old-run and fault scenarios. Tokens cross this boundary only
 * on private pipes into controller memory ("quarantined fixtures"); no role exposes an export command, and nothing is logged.
 */
export interface HarnessPort {
  /** Issues one real token per voucher (base64url vouchers) from inside the client container. */
  issue(client: ClientId, manifest: Manifest, vouchers: string[]): Promise<Uint8Array[]>;
  /** Presents each token once, in order, from inside the client container, and reports what the gateway answered. */
  present(client: ClientId, manifest: Manifest, tokens: Uint8Array[]): Promise<{ status: number; label: string | null }[]>;
}

/** Real faults the controller can inject to exercise fail-closed behavior. Each affects the live deployment, nothing is simulated. */
export type RedisFault = 'script-flush' | 'clock-delete' | 'policy-corrupt' | 'clock-regress' | 'redis-stop';
export interface FaultPort {
  redis(kind: RedisFault): Promise<void>;
  /** Re-loads the replay scripts after a fault, to prove that live repair does not revive a closed run. */
  reloadScripts(): Promise<void>;
  pauseOrigin(): Promise<void>;
  unpauseOrigin(): Promise<void>;
}

/** In-memory store for credentials that deliberately survive a reset inside the controller (S13 only). Never serialized. */
export class Vault {
  readonly #items = new Map<string, Uint8Array[]>();
  put(key: string, tokens: Uint8Array[]): void { this.#items.set(key, tokens.map((t) => Uint8Array.from(t))); }
  take(key: string): Uint8Array[] | undefined { const v = this.#items.get(key); this.#items.delete(key); return v; }
  clear(): void { for (const list of this.#items.values()) for (const t of list) t.fill(0); this.#items.clear(); }
  toJSON(): string { return '[Vault]'; }
}

export type OriginCounts = Readonly<{ protected_requests_received: number; generation_mismatches: number; resources_served: number }>;
