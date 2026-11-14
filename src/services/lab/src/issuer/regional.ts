import { randomBytes } from 'node:crypto';
import { connect, type Socket } from 'node:net';
import {
  canonicalJson, decodeBase64Url, encodeBase64Url, hex, PROTOCOL, sha256, voucherDigest,
} from '../../../../contracts/lib/index.ts';
import {
  REGIONAL, arcRpcMacInput, encodeRegionalFrame, regionalPolicyDigest, requireRegionalWindow,
  validateArcRequest, validateRegionalPolicy, type ArcRequest, type RegionalPolicy,
} from '../../../../contracts/lib/regional.ts';
import {
  authenticateArcResponse, decodeRegionalPublicRequest, regionalMac, validateArcBootstrap,
  validateRegionalPublicResponse, type ArcBootstrap,
} from '../../../../contracts/lib/regional-wire.ts';
import type { IssuerSigner } from '../protocol.ts';
import { AdmissionGate } from './admission.ts';
import type { IssueOutput } from './issuance.ts';
import type { VoucherStore } from './vouchers.ts';

export type RegionalArcIssueOptions = {
  bootstrap: ArcBootstrap;
  endpoint: { host: string; port: number };
  issueKey: Uint8Array;
};
export type RegionalAdmissionOptions = {
  policy: RegionalPolicy;
  signer: IssuerSigner;
  vouchers: VoucherStore;
  limits?: typeof PROTOCOL.issuer_limits;
  isLive?: () => boolean;
  now?: () => number;
  onFault?: () => void;
  arc?: RegionalArcIssueOptions;
};

const output = (status: number, value: unknown): IssueOutput => ({
  status, contentType: 'application/json', body: Buffer.from(canonicalJson(value), 'utf8'),
});
const refused = (status: number, error: string) => output(status, { error });
class ArcIssueRefusal extends Error {}

/** One immutable server-selected generation. Entitlements are removed before any signing starts. */
export class RegionalAdmission {
  readonly #policy: RegionalPolicy;
  readonly #signer: IssuerSigner;
  readonly #vouchers: VoucherStore;
  readonly #gate: AdmissionGate;
  readonly #now: () => number;
  readonly #live: () => boolean;
  readonly #fault: () => void;
  readonly #arc: RegionalArcIssueOptions | undefined;
  readonly #sockets = new Set<Socket>();
  #open = false;
  #closed = false;
  #reserved = 0;
  #successes = 0;
  #failures = 0;

  constructor(options: RegionalAdmissionOptions) {
    this.#policy = validateRegionalPolicy(options.policy);
    this.#signer = options.signer;
    this.#vouchers = options.vouchers;
    this.#now = options.now ?? Date.now;
    this.#live = options.isLive ?? (() => true);
    this.#fault = options.onFault ?? (() => {});
    const limits = options.limits ?? PROTOCOL.issuer_limits;
    this.#gate = new AdmissionGate(limits.active_signings, limits.queue_depth, limits.queue_wait_ms);
    if (this.#policy.type2_key_id !== null && this.#policy.type2_key_id !== hex(sha256(this.#signer.publicKeySpki))) {
      throw new Error('regional-issuer-configuration');
    }
    if (this.#policy.profile === 'arc') {
      if (!options.arc || options.arc.issueKey.length !== 32) throw new Error('regional-issuer-configuration');
      const bootstrap = validateArcBootstrap(options.arc.bootstrap, {
        run_id: this.#policy.run_id, arc_implementation_revision: this.#policy.arc_implementation_revision!,
      });
      if (bootstrap.arc_key_id !== this.#policy.arc_key_id) throw new Error('regional-issuer-configuration');
      this.#arc = { bootstrap, endpoint: { ...options.arc.endpoint }, issueKey: Uint8Array.from(options.arc.issueKey) };
    } else if (options.arc) throw new Error('regional-issuer-configuration');
  }

  get counters() { return { issuance_successes: this.#successes, issuance_failures: this.#failures }; }
  get reservedEntitlements(): number { return this.#reserved; }
  setOpen(open: boolean): void {
    if (open && this.#closed) throw new Error('regional-issuer-closed');
    this.#open = open;
    if (!open) {
      this.#closed = true;
      this.#gate.cancelQueued();
      for (const socket of this.#sockets) socket.destroy();
      this.#arc?.issueKey.fill(0);
    }
  }
  drain(timeoutMs: number): Promise<boolean> { return this.#gate.whenIdle(timeoutMs); }
  #current(): boolean {
    if (!this.#open || !this.#live()) return false;
    try { requireRegionalWindow(this.#policy, this.#now()); return true; } catch { return false; }
  }

  directory(): IssueOutput {
    if (!this.#current()) return refused(503, 'issuance-unavailable');
    if (!this.#arc) return refused(404, 'not-found');
    const body = {
      contract_version: REGIONAL.contract_version, policy_digest: regionalPolicyDigest(this.#policy),
      arc_key_id: this.#arc.bootstrap.arc_key_id,
      arc_implementation_revision: this.#arc.bootstrap.arc_implementation_revision,
      issuer_params_b64url: this.#arc.bootstrap.issuer_params_b64url,
    };
    validateRegionalPublicResponse('arc-directory', body, this.#policy);
    return output(200, body);
  }

  async handleEnrollment(wire: Uint8Array): Promise<IssueOutput> {
    if (!this.#current()) return this.#refuse(503, 'issuance-unavailable');
    let body: Record<string, unknown>;
    let requests: Uint8Array[];
    try {
      body = decodeRegionalPublicRequest('enroll', wire, this.#policy);
      requests = (body['blinded_requests_b64url'] as string[]).map(value => Uint8Array.from(Buffer.from(value, 'base64url')));
      if (this.#policy.profile !== 'arc') {
        const truncatedKey = sha256(this.#signer.publicKeySpki).at(-1)!;
        if (requests.some(request => request.length !== PROTOCOL.request_bytes
          || ((request[0]! << 8) | request[1]!) !== PROTOCOL.token_type || request[2] !== truncatedKey)) {
          return this.#refuse(422, 'issuance-request-invalid');
        }
      }
    } catch { return this.#refuse(400, 'bad-request'); }
    const release = await this.#gate.acquire();
    if (!release) return this.#refuse(503, 'issuance-busy');
    try {
      if (!this.#current()) return this.#refuse(503, 'issuance-unavailable');
      const voucher = decodeBase64Url(body['enrollment_voucher_b64url'] as string, 32, false);
      // Synchronous consume and reserve precede the first asynchronous cryptographic operation.
      const digest = voucherDigest(voucher);
      voucher.fill(0);
      if (this.#reserved >= this.#policy.admitted_entitlements || !this.#vouchers.consume(digest)) {
        return this.#refuse(403, 'issuance-not-authorized');
      }
      this.#reserved++;
      try {
        const responses: string[] = [];
        for (const request of requests) {
          if (!this.#current()) return this.#refuse(503, 'issuance-unavailable');
          const response = this.#arc
            ? await this.#issueArc(Buffer.from(request).toString('base64url'), randomBytes(16).toString('hex'))
            : encodeBase64Url(await this.#signer.sign(request), false);
          responses.push(response);
        }
        if (!this.#current()) return this.#refuse(503, 'issuance-unavailable');
        const result = {
          contract_version: REGIONAL.contract_version, policy_digest: regionalPolicyDigest(this.#policy),
          profile: this.#policy.profile, responses_b64url: responses,
        };
        validateRegionalPublicResponse('enroll', result, this.#policy);
        this.#successes += responses.length;
        return output(200, result);
      } catch (error) {
        return error instanceof ArcIssueRefusal
          ? this.#refuse(403, 'issuance-not-authorized')
          : this.#refuse(503, 'issuance-unavailable');
      }
    } finally { release(); }
  }

  async #issueArc(blinded: string, grantId: string): Promise<string> {
    const arc = this.#arc!;
    const request: ArcRequest = {
      contract_version: REGIONAL.contract_version, run_id: this.#policy.run_id,
      policy_digest: regionalPolicyDigest(this.#policy), request_id: randomBytes(16).toString('hex'),
      service_incarnation: arc.bootstrap.service_incarnation, operation: 'issue',
      grant_id: grantId, blinded_request_b64url: blinded,
    };
    validateArcRequest(request, this.#policy);
    const frame = encodeRegionalFrame(request, regionalMac(arc.issueKey, arcRpcMacInput('request', 'issue', request)));
    try {
      const wire = await new Promise<Uint8Array>((resolve, reject) => {
        const socket = connect(arc.endpoint);
        this.#sockets.add(socket);
        let data = Buffer.alloc(0), done = false;
        const finish = (value?: Uint8Array) => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          clearTimeout(connectTimer);
          this.#sockets.delete(socket);
          socket.destroy();
          if (value) resolve(value); else reject(new Error('arc-issue-unavailable'));
        };
        const timer = setTimeout(() => finish(), REGIONAL.arc_rpc_timeout_ms);
        const connectTimer = setTimeout(() => finish(), REGIONAL.arc_rpc_connect_timeout_ms);
        socket.once('connect', () => { clearTimeout(connectTimer); socket.write(frame); });
        socket.on('data', (chunk: Buffer) => {
          data = Buffer.concat([data, chunk]);
          if (data.length > REGIONAL.rpc_frame_max_bytes) return finish();
          const newline = data.indexOf(10);
          if (newline >= 0) finish(newline === data.length - 1 ? data : undefined);
        });
        socket.once('error', () => finish());
        socket.once('close', () => finish());
      });
      const reply = authenticateArcResponse(wire, request, this.#policy, arc.issueKey);
      if (reply.status === 'issued') return reply.credential_response_b64url;
      if (reply.status === 'refused' && ['invalid-input', 'invalid-proof', 'window-closed'].includes(reply.code)) {
        throw new ArcIssueRefusal();
      }
      throw new Error('arc-issue-unavailable');
    } catch (error) {
      if (error instanceof ArcIssueRefusal) throw error;
      this.setOpen(false);
      this.#fault();
      throw new Error('arc-issue-failed');
    }
  }

  #refuse(status: number, error: string): IssueOutput {
    this.#failures++;
    return refused(status, error);
  }
}
