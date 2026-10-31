// Node Privacy Pass client for the lab (M02): challenge, issuance, finalization, inventory, redemption, all through
// a pinned CONNECT/TLS path. One library Client per outstanding issuance; vouchers are removed before use and never
// reused; tokens and vouchers stay in memory. This is the lab client, not a browser extension.
import { request, type Agent } from 'node:https';
import type { IncomingMessage } from 'node:http';
import { Token, TOKEN_TYPES } from '@cloudflare/privacypass-ts';
import {
  PROTOCOL, ContractError, decodeBase64Url, encodeBase64Url, hex, sha256, type Manifest,
} from '../../../../contracts/lib/index.ts';
import { LabIssuance, verifyTokenSignature } from '../protocol.ts';
import { REQUEST_TYPE, RESPONSE_TYPE } from '../issuer/issuance.ts';
import { DIRECTORY_PATH, DIRECTORY_TYPE } from '../issuer/directory.ts';
import { parseChallenge, plausibleEpochs, type ParsedChallenge } from './challenge.ts';
import { TunnelAgent, connectTls, type TunnelOptions } from './tunnel.ts';
import { TokenInventory } from './inventory.ts';
import type { ClientVouchers } from './vouchers.ts';

export type ClientErrorCode =
  | 'transport' | 'redirect-refused' | 'response-too-large' | 'unexpected-response' | 'challenge-unavailable'
  | 'no-voucher' | 'no-token' | 'issuance-refused' | 'issuance-invalid' | 'directory-mismatch' | 'client-closed';
/** Fixed code plus (for refusals) the HTTP status. Never carries bodies, vouchers, tokens or exception text. */
export class LabClientError extends Error {
  readonly code: ClientErrorCode;
  readonly status: number | undefined;
  constructor(code: ClientErrorCode, status?: number) { super(code); this.name = 'LabClientError'; this.code = code; this.status = status; }
}

export type ClientConfig = {
  manifest: Manifest;
  /** Proxy to dial. In the lab this is manifest.endpoints.proxy_http; tests point it at a local stub. */
  proxy: { host: string; port: number };
  /** Lab CA that signed the issuer and gateway certificates. */
  caPem: string;
  vouchers: ClientVouchers;
  now?: () => number;
  requestTimeoutMs?: number;
};
/**
 * Node's Agent counts a socket only after an asynchronous createConnection finishes, so maxSockets alone does not
 * bound concurrent tunnels. This gate caps in-flight exchanges per destination at the manifest socket limit, which
 * caps tunnels, because each exchange holds at most one and finished keep-alive sockets are reused.
 */
class Gate {
  readonly #max: number;
  #active = 0;
  readonly #waiting: (() => void)[] = [];
  constructor(max: number) { this.#max = max; }
  async enter(): Promise<() => void> {
    if (this.#active >= this.#max) await new Promise<void>((resolve) => this.#waiting.push(resolve));
    else this.#active += 1;
    let left = false;
    // Release after the agent has had a tick to return the socket to its free list.
    return () => { if (left) return; left = true; setImmediate(() => { const next = this.#waiting.shift(); if (next) next(); else this.#active -= 1; }); };
  }
}
type Reply = { status: number; headers: IncomingMessage['headers']; rawHeaders: string[]; body: Buffer };

export class LabClient {
  readonly tokens: TokenInventory;
  readonly #m: Manifest;
  readonly #vouchers: ClientVouchers;
  readonly #issuerKey: Uint8Array;
  readonly #issuerAgent: Agent;
  readonly #gatewayAgent: Agent;
  readonly #gates = new Map<Agent, Gate>();
  readonly #tunnel: TunnelOptions;
  readonly #now: () => number;
  readonly #timeoutMs: number;

  constructor(cfg: ClientConfig) {
    this.#m = cfg.manifest;
    this.#vouchers = cfg.vouchers;
    this.#now = cfg.now ?? Date.now;
    this.#timeoutMs = cfg.requestTimeoutMs ?? PROTOCOL.issuer_limits.request_timeout_ms;
    this.#issuerKey = decodeBase64Url(cfg.manifest.token_key_spki_b64url);
    this.tokens = new TokenInventory(cfg.manifest.limits.client.inventory_max);
    const allowedHosts = [cfg.manifest.issuer_name, cfg.manifest.origin_name];
    const common = { proxy: cfg.proxy, caPem: cfg.caPem, allowedHosts };
    this.#tunnel = { ...common, maxSockets: cfg.manifest.limits.client.gateway_sockets };
    this.#issuerAgent = new TunnelAgent({ ...common, maxSockets: cfg.manifest.limits.client.issuer_sockets });
    this.#gatewayAgent = new TunnelAgent({ ...common, maxSockets: cfg.manifest.limits.client.gateway_sockets });
    this.#gates.set(this.#issuerAgent, new Gate(cfg.manifest.limits.client.issuer_sockets));
    this.#gates.set(this.#gatewayAgent, new Gate(cfg.manifest.limits.client.gateway_sockets));
  }

  #closed = false;
  /** After close() no new connection is opened: a scenario still running when the role is fenced cannot present anything. */
  close(): void { this.#closed = true; this.#issuerAgent.destroy(); this.#gatewayAgent.destroy(); this.tokens.clear(); this.#vouchers.clear(); }

  /** Public directory must be exactly what the manifest pinned; a different key or URI is refused, not adopted. */
  async checkDirectory(): Promise<void> {
    const r = await this.#exchange(this.#issuerAgent, this.#m.issuer_name, { method: 'GET', path: DIRECTORY_PATH }, 4096);
    if (r.status !== 200 || r.headers['content-type'] !== DIRECTORY_TYPE) throw new LabClientError('unexpected-response', r.status);
    let dir: { [k: string]: unknown };
    try { dir = JSON.parse(r.body.toString('utf8')) as { [k: string]: unknown }; } catch { throw new LabClientError('directory-mismatch'); }
    const keys = dir['token-keys'] as { 'token-type'?: unknown; 'token-key'?: unknown }[] | undefined;
    if (dir['issuer-request-uri'] !== this.#m.issuer_request_uri || !Array.isArray(keys) || keys.length !== 1
      || keys[0]!['token-type'] !== PROTOCOL.token_type || keys[0]!['token-key'] !== this.#m.token_key_spki_b64url) throw new LabClientError('directory-mismatch');
  }

  /** Unauthenticated GET; the 401 must carry exactly one acceptable challenge for the pinned key and run. */
  async fetchChallenge(): Promise<ParsedChallenge> {
    const r = await this.#exchange(this.#gatewayAgent, this.#m.origin_name, { method: 'GET', path: '/resource' }, PROTOCOL.gateway_common.origin_body_max_bytes);
    if (r.status !== 401) throw new LabClientError('challenge-unavailable', r.status);
    const values = headerValues(r.rawHeaders, 'www-authenticate');
    try { return parseChallenge(values, this.#m, plausibleEpochs(this.#m, this.#now())); }
    catch (e) { if (e instanceof ContractError) throw new LabClientError('challenge-unavailable'); throw e; }
  }

  /**
   * One issuance: take a voucher (gone from this point regardless of outcome), blind with a fresh library Client,
   * POST, finalize, verify publicly against the pinned key, then store. Exactly one attempt per voucher.
   */
  async obtainToken(parsed: ParsedChallenge): Promise<void> {
    if (this.tokens.size >= this.#m.limits.client.inventory_max) throw new LabClientError('no-token');
    this.tokens.add(parsed.epoch, await this.issueWire(parsed.challenge));
  }

  /**
   * One real issuance for ANY challenge (including a deliberately wrong-context one) returned as bytes instead of stored.
   * Trusted scenario harness only: the caller owns the token and must not retain it past the scenario. Same one-voucher,
   * one-attempt rules as obtainToken; the issuer signs blindly and cannot know which context the challenge carries.
   */
  async issueWire(challenge: import('@cloudflare/privacypass-ts').TokenChallenge): Promise<Uint8Array> {
    const voucher = this.#vouchers.take();
    if (!voucher) throw new LabClientError('no-voucher');
    const issuance = await LabIssuance.begin(challenge, this.#issuerKey);
    const r = await this.#exchange(this.#issuerAgent, this.#m.issuer_name, {
      method: 'POST', path: new URL(this.#m.issuer_request_uri).pathname, body: issuance.requestWire,
      headers: { 'Content-Type': REQUEST_TYPE, Accept: RESPONSE_TYPE, 'X-Lab-Voucher': encodeBase64Url(voucher, false) },
    }, 4096);
    voucher.fill(0);
    if (r.status !== 200) throw new LabClientError('issuance-refused', r.status);
    if (r.headers['content-type'] !== RESPONSE_TYPE || r.body.length !== PROTOCOL.response_bytes) throw new LabClientError('issuance-invalid');
    let wire: Uint8Array;
    try {
      wire = await issuance.finalize(r.body);
      const token = Token.deserialize(TOKEN_TYPES.BLIND_RSA, wire);
      const expected = sha256(challenge.serialize());
      if (hex(token.authInput.challengeDigest) !== hex(expected) || hex(token.authInput.tokenKeyId) !== this.#m.token_key_id
        || !(await verifyTokenSignature(this.#issuerKey, wire))) throw new Error('token-invalid');
    } catch { throw new LabClientError('issuance-invalid'); }
    return wire;
  }

  /**
   * For the trusted scenario harness only: one issuance POST with caller-supplied bytes and voucher, returning the HTTP
   * status and (on 200) the response body. It is not used by ordinary client flow and keeps nothing.
   */
  async issuanceAttempt(requestWire: Uint8Array, voucher: Uint8Array | null): Promise<{ status: number; body: Buffer }> {
    const r = await this.#exchange(this.#issuerAgent, this.#m.issuer_name, {
      method: 'POST', path: new URL(this.#m.issuer_request_uri).pathname, body: requestWire,
      headers: { 'Content-Type': REQUEST_TYPE, Accept: RESPONSE_TYPE, ...(voucher ? { 'X-Lab-Voucher': encodeBase64Url(voucher, false) } : {}) },
    }, 4096);
    return { status: r.status, body: r.body };
  }

  /** Presents one inventoried token (removed first: a token is offered at most once). */
  async redeem(epoch: number): Promise<{ status: number; wwwAuthenticate: string[] }> {
    const wire = this.tokens.take(epoch);
    if (!wire) throw new LabClientError('no-token');
    return this.redeemWire(wire);
  }

  /** For the trusted scenario harness: present exact bytes (including deliberately wrong ones). */
  async redeemWire(wire: Uint8Array): Promise<{ status: number; wwwAuthenticate: string[]; label: string | null }> {
    const r = await this.#exchange(this.#gatewayAgent, this.#m.origin_name, {
      method: 'GET', path: '/resource', headers: { Authorization: `PrivateToken token="${encodeBase64Url(wire)}"` },
    }, PROTOCOL.gateway_common.origin_body_max_bytes);
    return { status: r.status, wwwAuthenticate: headerValues(r.rawHeaders, 'www-authenticate'), label: errorLabel(r.body) };
  }

  /**
   * Security kit: send exact bytes to the gateway over a verified tunnel and report what came back. This is how duplicate
   * headers, bad framing and oversize inputs are exercised; it is fixed harness code, reachable only from allowlisted
   * scenarios, never from a control message. The socket count obeys the same manifest bound as ordinary requests.
   */
  async rawGateway(bytes: Uint8Array, options: { timeoutMs?: number; maxResponse?: number } = {}): Promise<{ status: number | null; label: string | null; closed: boolean; connected: boolean }> {
    if (this.#closed) return { status: null, label: null, closed: true, connected: false };
    const gate = this.#gates.get(this.#gatewayAgent)!;
    const leave = await gate.enter();
    const timeoutMs = options.timeoutMs ?? 5000, max = options.maxResponse ?? 32768;
    try {
      let socket: import('node:tls').TLSSocket;
      try { socket = await connectTls(this.#tunnel, this.#m.origin_name); } catch { return { status: null, label: null, closed: true, connected: false }; }
      return await new Promise((resolve) => {
        let data = Buffer.alloc(0), done = false;
        const finish = (closed: boolean) => {
          if (done) return; done = true; clearTimeout(timer); socket.destroy();
          const text = data.toString('latin1');
          const m = /^HTTP\/1\.1 (\d{3}) /.exec(text);
          const body = data.subarray(Math.max(0, data.indexOf('\r\n\r\n') + 4));
          resolve({ status: m ? Number(m[1]) : null, label: errorLabel(body), closed, connected: true });
        };
        const timer = setTimeout(() => finish(false), timeoutMs);
        socket.on('data', (c: Buffer) => {
          data = Buffer.concat([data, c]);
          const end = data.indexOf('\r\n\r\n');
          if (end >= 0) {
            const len = Number(/content-length:\s*(\d+)/i.exec(data.subarray(0, end).toString('latin1'))?.[1] ?? 0);
            if (data.length >= end + 4 + len) finish(false);
          }
          if (data.length > max) finish(false);
        });
        socket.on('close', () => finish(true)); socket.on('error', () => finish(true));
        socket.write(Buffer.from(bytes));
      });
    } finally { leave(); }
  }

  async #exchange(agent: Agent, host: string, o: { method: string; path: string; headers?: Record<string, string>; body?: Uint8Array }, maxBody: number): Promise<Reply> {
    if (this.#closed) throw new LabClientError('client-closed');
    const leave = await this.#gates.get(agent)!.enter();
    try { return await this.#send(agent, host, o, maxBody); } finally { leave(); }
  }

  #send(agent: Agent, host: string, o: { method: string; path: string; headers?: Record<string, string>; body?: Uint8Array }, maxBody: number): Promise<Reply> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const done = (f: () => void) => { if (!settled) { settled = true; clearTimeout(deadline); f(); } };
      const req = request({ agent, host, port: 443, servername: host, method: o.method, path: o.path,
        headers: { ...(o.body ? { 'Content-Length': String(o.body.length) } : {}), ...o.headers } }, (res) => {
        if (res.statusCode! >= 300 && res.statusCode! < 400) { res.destroy(); req.destroy(); return done(() => reject(new LabClientError('redirect-refused'))); }
        const chunks: Buffer[] = []; let total = 0;
        res.on('data', (c: Buffer) => {
          total += c.length;
          if (total > maxBody) { res.destroy(); req.destroy(); done(() => reject(new LabClientError('response-too-large'))); return; }
          chunks.push(c);
        });
        res.on('end', () => done(() => resolve({ status: res.statusCode!, headers: res.headers, rawHeaders: res.rawHeaders, body: Buffer.concat(chunks) })));
        res.on('error', () => done(() => reject(new LabClientError('transport'))));
      });
      const deadline = setTimeout(() => { req.destroy(); done(() => reject(new LabClientError('transport'))); }, this.#timeoutMs);
      req.on('error', () => done(() => reject(new LabClientError('transport'))));
      req.end(o.body ? Buffer.from(o.body) : undefined);
    });
  }
}

/** The gateway's fixed JSON error label (`{"error":"token-..."}`), or null if absent or not a known label. */
export function errorLabel(body: Buffer): string | null {
  try {
    const e = (JSON.parse(body.toString('utf8')) as { error?: unknown }).error;
    return typeof e === 'string' && Object.hasOwn(PROTOCOL.gateway_results, e) ? e : null;
  } catch { return null; }
}

function headerValues(raw: string[], name: string): string[] {
  const out: string[] = [];
  for (let i = 0; i + 1 < raw.length; i += 2) if (raw[i]!.toLowerCase() === name) out.push(raw[i + 1]!);
  return out;
}
