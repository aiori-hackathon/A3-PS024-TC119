// Control links. HelperLink drives a role's in-container control helper over a persistent stdin/stdout pipe;
// InProcessLink wraps a role object for tests. Both validate every frame against the frozen schemas, correlate replies
// by request_id (never by arrival order), bound outstanding requests, and fail every pending request when the link is
// lost. A link never echoes request or reply contents into an error.
import type { ChildProcess } from 'node:child_process';
import { PROTOCOL, validateControlRequest, validateControlResponse } from '../../../../contracts/lib/index.ts';
import type { Json, RoleLink, RoleName } from './ports.ts';

export type LinkErrorCode = 'timeout' | 'link-lost' | 'protocol' | 'too-many-pending';
export class LinkError extends Error {
  readonly code: LinkErrorCode;
  constructor(code: LinkErrorCode) { super(code); this.name = 'LinkError'; this.code = code; }
}
const MAX_PENDING = 9; // eight ordinary requests plus the reserved FENCE path (plan section 5.1)
const MAX_FRAME = PROTOCOL.control_message_max_bytes;

type Waiter = { resolve: (r: Json) => void; reject: (e: LinkError) => void; timer: NodeJS.Timeout };

abstract class BaseLink implements RoleLink {
  readonly role: RoleName;
  protected readonly pending = new Map<string, Waiter>();
  protected dead = false;
  readonly #defaultTimeoutMs: number;
  constructor(role: RoleName, defaultTimeoutMs: number) { this.role = role; this.#defaultTimeoutMs = defaultTimeoutMs; }

  send(request: Json, timeoutMs = this.#defaultTimeoutMs): Promise<Json> {
    if (this.dead) return Promise.reject(new LinkError('link-lost'));
    let id: string;
    try { validateControlRequest(request); id = request['request_id'] as string; } catch { return Promise.reject(new LinkError('protocol')); }
    if (this.pending.has(id) || (this.pending.size >= MAX_PENDING)) return Promise.reject(new LinkError('too-many-pending'));
    const line = JSON.stringify(request);
    if (Buffer.byteLength(line, 'utf8') > MAX_FRAME) return Promise.reject(new LinkError('protocol'));
    return new Promise<Json>((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new LinkError('timeout')); }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      try { this.write(line); } catch { this.fail(); }
    });
  }
  protected abstract write(line: string): void;
  abstract close(): void;

  /** Called with one reply frame. A bad or unsolicited frame poisons the whole link. */
  protected deliver(raw: unknown): void {
    let reply: Json;
    try { validateControlResponse(raw); reply = raw as Json; } catch { this.fail(); return; }
    const waiter = this.pending.get(reply['request_id']);
    if (!waiter) { this.fail(); return; }
    clearTimeout(waiter.timer);
    this.pending.delete(reply['request_id']);
    waiter.resolve(reply);
  }
  protected fail(): void {
    this.dead = true;
    for (const [id, w] of this.pending) { clearTimeout(w.timer); w.reject(new LinkError('link-lost')); this.pending.delete(id); }
    this.close();
  }
}

export class HelperLink extends BaseLink {
  readonly #child: ChildProcess;
  #buffer = '';
  constructor(role: RoleName, child: ChildProcess, defaultTimeoutMs = 10_000) {
    super(role, defaultTimeoutMs);
    this.#child = child;
    child.stdout!.setEncoding('utf8');
    child.stdout!.on('data', (chunk: string) => {
      this.#buffer += chunk;
      if (this.#buffer.length > MAX_FRAME * 2) { this.fail(); return; }
      let at: number;
      while ((at = this.#buffer.indexOf('\n')) >= 0) {
        const line = this.#buffer.slice(0, at); this.#buffer = this.#buffer.slice(at + 1);
        let parsed: unknown;
        try { parsed = JSON.parse(line); } catch { this.fail(); return; }
        this.deliver(parsed);
      }
    });
    child.stderr?.resume(); // discarded: helper stderr is a fixed token and must never reach logs here
    child.on('close', () => this.fail());
    child.on('error', () => this.fail());
    child.stdin!.on('error', () => this.fail());
  }
  protected write(line: string): void { this.#child.stdin!.write(line + '\n'); }
  close(): void {
    this.dead = true;
    try { this.#child.stdin?.end(); } catch { /* already closed */ }
    this.#child.kill();
  }
}

/** Test link around a role object's `handle`. Requests and replies are cloned, as they would be on a real wire. */
export class InProcessLink extends BaseLink {
  readonly #handle: (raw: unknown) => Promise<Json>;
  constructor(role: RoleName, handle: (raw: unknown) => Promise<Json>, defaultTimeoutMs = 10_000) { super(role, defaultTimeoutMs); this.#handle = handle; }
  protected write(line: string): void {
    void this.#handle(JSON.parse(line)).then((reply) => { if (!this.dead) this.deliver(structuredClone(reply)); }, () => this.fail());
  }
  close(): void { this.dead = true; }
}
