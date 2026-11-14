import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { canonicalJson, ContractError, PROTOCOL } from '../../../../contracts/lib/index.ts';
import { REGIONAL, type RegionalPolicy } from '../../../../contracts/lib/regional.ts';
import { decodeCanonicalRegionalJson } from '../../../../contracts/lib/regional-wire.ts';
import type { ArcClientHelper } from './regional.ts';

/** Private child pipes hold opaque pending/wallet handles. Secrets remain inside the Rust child. */
export class ProcessArcClientHelper implements ArcClientHelper {
  readonly #child: ChildProcessWithoutNullStreams;
  readonly #exited: Promise<void>;
  #pending: string | undefined;
  #wallet: string | undefined;
  #closed = false;
  #chain: Promise<unknown> = Promise.resolve();
  #reply: { resolve: (value: Record<string, unknown>) => void; reject: () => void; timer: NodeJS.Timeout } | undefined;
  #buffer = Buffer.alloc(0);

  constructor(executable: string) {
    this.#child = spawn(executable, [], { stdio: 'pipe', windowsHide: true });
    this.#exited = new Promise(resolve => { this.#child.once('exit', () => resolve()); this.#child.once('error', () => resolve()); });
    this.#child.stdout.on('data', (chunk: Buffer) => {
      if (!this.#reply) return this.close();
      this.#buffer = Buffer.concat([this.#buffer, chunk]);
      if (this.#buffer.length > REGIONAL.rpc_frame_max_bytes) return this.close();
      const newline = this.#buffer.indexOf(10);
      if (newline < 0) return;
      if (newline !== this.#buffer.length - 1) return this.close();
      try {
        const value = decodeCanonicalRegionalJson(this.#buffer, true);
        if (!value || typeof value !== 'object' || Array.isArray(value)) return this.close();
        const reply = this.#reply;
        clearTimeout(reply.timer);
        this.#reply = undefined;
        this.#buffer = Buffer.alloc(0);
        reply.resolve(value as Record<string, unknown>);
      } catch { this.close(); }
    });
    // Diagnostic text is deliberately discarded. It may contain third-party library details.
    this.#child.stderr.resume();
    this.#child.on('error', () => this.close());
    this.#child.on('exit', () => this.close());
    this.#child.stdin.on('error', () => this.close());
  }

  #call(body: unknown): Promise<Record<string, unknown>> {
    const operation = this.#chain.then(() => {
      if (this.#closed) throw new ContractError('regional-helper-unavailable');
      return new Promise<Record<string, unknown>>((resolve, reject) => {
        const wire = Buffer.from(canonicalJson(body) + '\n', 'utf8');
        if (wire.length > REGIONAL.rpc_frame_max_bytes) return reject(new ContractError('regional-helper-input'));
        const timer = setTimeout(() => { void this.close(); }, PROTOCOL.issuer_limits.request_timeout_ms);
        this.#reply = { resolve, reject: () => reject(new ContractError('regional-helper-unavailable')), timer };
        this.#child.stdin.write(wire);
      });
    });
    this.#chain = operation.catch(() => undefined);
    return operation;
  }

  async begin(policy: RegionalPolicy, issuerParams: string): Promise<string> {
    const reply = await this.#call({ operation: 'create-request', policy, issuer_params_b64url: issuerParams });
    if (Object.keys(reply).sort().join(',') !== 'blinded_request_b64url,pending_handle,status'
      || reply['status'] !== 'created' || !handle(reply['pending_handle']) || !blob(reply['blinded_request_b64url'])) {
      this.close(); throw new ContractError('regional-helper-invalid');
    }
    this.#pending = reply['pending_handle'];
    return reply['blinded_request_b64url'];
  }
  async finalize(response: string): Promise<void> {
    if (!this.#pending) throw new ContractError('regional-helper-state');
    const pending = this.#pending;
    this.#pending = undefined;
    const reply = await this.#call({ operation: 'finalize-credential', pending_handle: pending, credential_response_b64url: response });
    if (Object.keys(reply).sort().join(',') !== 'status,wallet_handle'
      || reply['status'] !== 'finalized' || !handle(reply['wallet_handle'])) {
      this.close(); throw new ContractError('regional-helper-invalid');
    }
    this.#wallet = reply['wallet_handle'];
  }
  async present(slot?: number): Promise<string> {
    if (!this.#wallet) throw new ContractError('regional-helper-state');
    const reply = await this.#call({ operation: 'present', wallet_handle: this.#wallet, ...(slot === undefined ? {} : { slot }) });
    if (Object.keys(reply).sort().join(',') !== 'presentation_b64url,status'
      || reply['status'] !== 'presented' || !blob(reply['presentation_b64url'])) {
      this.close(); throw new ContractError('regional-helper-invalid');
    }
    return reply['presentation_b64url'];
  }
  close(): Promise<void> {
    if (this.#closed) return this.#exited;
    this.#closed = true;
    this.#pending = undefined;
    this.#wallet = undefined;
    if (this.#reply) { clearTimeout(this.#reply.timer); this.#reply.reject(); this.#reply = undefined; }
    this.#buffer.fill(0);
    this.#child.kill();
    return this.#exited;
  }
}

const handle = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value);
function blob(value: unknown): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > 32768) return false;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length > 0 && bytes.length <= REGIONAL.arc_blob_max_bytes && bytes.toString('base64url') === value;
}
