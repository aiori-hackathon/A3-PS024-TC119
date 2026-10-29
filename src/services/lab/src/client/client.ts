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
import { TunnelAgent } from './tunnel.ts';
import { TokenInventory } from './inventory.ts';
import type { ClientVouchers } from './vouchers.ts';

export type ClientErrorCode =
  | 'transport' | 'redirect-refused' | 'response-too-large' | 'unexpected-response' | 'challenge-unavailable'
  | 'no-voucher' | 'no-token' | 'issuance-refused' | 'issuance-invalid' | 'directory-mismatch';
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
    this.#issuerAgent = new TunnelAgent({ ...common, maxSockets: cfg.manifest.limits.client.issuer_sockets });
    this.#gatewayAgent = new TunnelAgent({ ...common, maxSockets: cfg.manifest.limits.client.gateway_sockets });
    this.#gates.set(this.#issuerAgent, new Gate(cfg.manifest.limits.client.issuer_sockets));
    this.#gates.set(this.#gatewayAgent, new Gate(cfg.manifest.limits.client.gateway_sockets));
  }

  close(): void { this.#issuerAgent.destroy(); this.#gatewayAgent.destroy(); this.tokens.clear(); this.#vouchers.clear(); }

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
    const voucher = this.#vouchers.take();
    if (!voucher) throw new LabClientError('no-voucher');
    const issuance = await LabIssuance.begin(parsed.challenge, this.#issuerKey);
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
      const expected = sha256(parsed.challenge.serialize());
      if (hex(token.authInput.challengeDigest) !== hex(expected) || hex(token.authInput.tokenKeyId) !== this.#m.token_key_id
        || !(await verifyTokenSignature(this.#issuerKey, wire))) throw new Error('token-invalid');
    } catch { throw new LabClientError('issuance-invalid'); }
    this.tokens.add(parsed.epoch, wire);
  }

  /** Presents one inventoried token (removed first: a token is offered at most once). */
  async redeem(epoch: number): Promise<{ status: number; wwwAuthenticate: string[] }> {
    const wire = this.tokens.take(epoch);
    if (!wire) throw new LabClientError('no-token');
    return this.redeemWire(wire);
  }

  /** For the trusted scenario harness: present exact bytes (including deliberately wrong ones). */
  async redeemWire(wire: Uint8Array): Promise<{ status: number; wwwAuthenticate: string[] }> {
    const r = await this.#exchange(this.#gatewayAgent, this.#m.origin_name, {
      method: 'GET', path: '/resource', headers: { Authorization: `PrivateToken token="${encodeBase64Url(wire)}"` },
    }, PROTOCOL.gateway_common.origin_body_max_bytes);
    return { status: r.status, wwwAuthenticate: headerValues(r.rawHeaders, 'www-authenticate') };
  }

  async #exchange(agent: Agent, host: string, o: { method: string; path: string; headers?: Record<string, string>; body?: Uint8Array }, maxBody: number): Promise<Reply> {
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

function headerValues(raw: string[], name: string): string[] {
  const out: string[] = [];
  for (let i = 0; i + 1 < raw.length; i += 2) if (raw[i]!.toLowerCase() === name) out.push(raw[i + 1]!);
  return out;
}
