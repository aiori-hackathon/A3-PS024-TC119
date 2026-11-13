# Regional integration contract

Contract **TF-PS024-REGIONAL-1.0.0**, candidate for counterpart acceptance, 14 November 2026.

This additive contract defines the new product interfaces. It does **not** enable ARC, holder verification or quotas in the current runtime. The accepted baseline `TF-PS024-1.0.0`, existing manifests, 600-second epochs, Type2 wire format and report schemas remain unchanged. Import regional helpers explicitly from `src/contracts/lib/regional.ts`; legacy consumers need no modification. Never label this document's structural tests as end-to-end security evidence.

## Policy and lifecycle

`src/contracts/regional-v1.json` supplies constants; `schemas/regional-*.json` supplies strict structural schemas. A regional policy is a separate controller-installed object, validated against the baseline manifest and bound by `baseline_config_digest`. Its digest is SHA-256 of `regionalBytes(domains.policy, policy)`.

Profiles are `ip`, `type2-bearer`, `arc` and `type2-holder`. Exactly one profile is accepted during a run. Client headers, UI selection or invalid proofs cannot change it. B0/B1 still mean gateway capacity profiles, not authorization algorithms.

- One regional run covers exactly one 60,000 ms window `[window_start_ms, window_end_ms)`, within the first baseline epoch. Controller setup must leave enough usable time; late setup is an incomplete run, not a reason to extend acceptance.
- Five admitted entitlements, each allowing five accepted uses, give an aggregate comparison budget of 25. The IP baseline instead shares that same aggregate budget at the observed shared egress. Its configured behavior is a comparison policy, not a claim about every IP limiter.
- Issuer admission receives one enrollment voucher/entitlement per client for that run, provisioned through private controller channels. It may issue one ARC credential or at most five Type2 signatures. It does not establish one human per credential. No live refill or client-triggered replacement.
- Type2 and ARC issuer keys are fresh for every regional run/window. A key used for an earlier window is never accepted in a later window. This is necessary because blind issuance cannot enforce which hidden challenge a client asks to sign: predictable future contexts under reusable keys could allow future-window stockpiling.
- Admit issuance and redemption only within the current window. For the next window, close/fence the old generation, confirm shutdown, rotate keys/state and create a fresh run starting no earlier than the previous window end. This first version uses explicit controller renewal, not seamless continuous production rotation.
- An early fault closes the run. Do not restore the consumed entitlement or resume/reset that generation to refill the current window. Trusted operator comparison resets create explicitly separate experiments and must be labelled as such; they are not public client operations.
- Admission reservation and ARC service grant use are atomic before signing begins. On uncertain signing/delivery, the allowance may be lost; never automatically refund or retry issuance. A five-request Type2 enrollment is all-budget-reserved before signing; partial crypto failure may deliver fewer tokens, never more than five.
- The quota is fixed-window and credential-scoped. It is not a guaranteed rolling-window rate limit, anti-Sybil mechanism or protection against willing parties sharing credential secrets.

The gateway's regional atomic spend operation must check the regional window using authoritative server time, policy/generation binding and intact state. The old 600-second claim's epoch check alone is insufficient. For holder mode it must also enforce authenticated nonce expiry at that final authorization point. Store tags through window end plus the baseline retention guard; that guard is storage retention only, never an acceptance grace. Preserve lease checks before forwarding, no retry after an uncertain claim, strong reset fencing and independent origin arrival evidence.

## Canonical encoding

`regionalBytes(domain, ...fields)` is UTF-8 of canonical JSON `[domain, ...fields]`, **without a trailing newline**. Reuse baseline `canonicalJson`: sorted object keys, ASCII strings, safe nonnegative integer numbers, no floats, duplicate fields, negative zero or alternate representations. Arrays preserve order. SHA-256 digests and HMAC-SHA256 MACs are lowercase 64-character hex. Binary fields use canonical **unpadded** base64url.

Rust must construct these exact bytes (including sorted nested keys). Do not MAC pretty JSON, insertion-order serialization or independently invented concatenation. The independent Python fixture includes exact hex inputs, frame bytes and MACs for interoperability. Its public test seeds and dummy token bytes must never become live credentials.

All endpoints reject duplicate JSON keys, extra properties, trailing data, unsupported versions and oversized input before expensive work. Enforce framing/size/time/concurrency limits before parsing/allocation. Structural validators do not prove MACs, signatures, proofs, live state or authorization. `JSON.parse` followed by schema validation cannot detect duplicate keys already discarded by parsing. A private RPC decoder can enforce exact byte equality with canonical re-encoding plus the final newline after bounded fatal-UTF8 parsing; reject noncanonical raw frames before using them. Public HTTP decoders require an equivalent duplicate-aware strategy.

## Product transport

All public product exchanges use the existing pinned TLS hostnames and shared CONNECT proxy. JSON body limit is 65,536 bytes including authentication envelopes; the ARC binary blob limit is 24,576 decoded bytes. Check actual library sizes in M01 before integration. Do not increase current socket/queue limits silently. Use POST bodies for potentially large ARC proofs instead of trying to fit them in the existing 8 KiB header budget.

The protected operation remains exactly `GET https://origin.lab.test/resource`, forwarded only to the configured private origin. Regional authentication POST routes are fixed transports for that operation and cannot select an upstream, method, query, body or alternative resource. No redirect follows and no public cache bypass.

| Endpoint | Request | Successful result |
| --- | --- | --- |
| `POST https://issuer.lab.test/regional/enroll` | `{contract_version, policy_digest, enrollment_voucher_b64url, profile, blinded_requests_b64url}` | `{contract_version, policy_digest, profile, responses_b64url}` |
| `GET /resource`, ordinary Type2 regional profile | Existing PrivateToken authorization with the regional challenge | Protected bytes after genuine verification and atomic spend |
| `POST /regional/arc/redeem` | `{contract_version, policy_digest, presentation_b64url}` | Protected bytes after ARC verification and atomic spend |
| `POST /regional/holder/challenge` | `{contract_version, policy_digest, public_key_spki_b64url}` | `{contract_version, policy_digest, challenge_b64url, token_key_spki_b64url}` |
| `POST /regional/holder/nonce` | `{contract_version, policy_digest, token_hash, public_key_spki_b64url}` | `{body, mac}` as the signed nonce below |
| `POST /regional/holder/redeem` | `{contract_version, policy_digest, token_b64url, proof}` | Protected bytes after token, context, nonce, signature and atomic spend checks |

Enrollment voucher is exactly 32 random bytes encoded unpadded base64url. `blinded_requests_b64url` and `responses_b64url` are arrays of exactly one item for ARC and exactly five for Type2. Type2 items retain their standard 259-byte issuance request/256-byte response encodings; ARC items use the pinned library adapter's agreed serialization. `profile` must equal installed server policy. Enrollment response is delivered only after the batch succeeds; uncertainty consumes the reservation and is reported honestly. Internal ARC issuance uses a separate random 16-byte `grant_id` for that reserved enrollment. The ARC component rejects reuse before signing, across concurrent requests, and does not replay cached credentials. Grant memory is bounded by the run's admitted entitlements and discarded only after fencing.

The holder challenge uses the existing RFC 9577 Type2 TokenChallenge structure and issuer/origin settings, with the holder context below. Type2 bearer regional challenges use `regionalContext(policy)` as the 32-byte redemption context. ARC library `request_context` and `presentation_context` use the corresponding domain-separated `regionalContext` outputs. These are TokenForge's application adapter choices; this JSON interface is not a claim of full ARC draft HTTP-wire conformance.

Public JSON success responses use status 200, no-store, nosniff and exact lengths. Regional JSON endpoints return fixed `{error}` with status 400 for malformed/unsupported input, 403 for refused authorization/admission (including invalid proof, repeated spend or closed window), and 503 for overload, dependency or unsafe-state uncertainty. Do not reflect submitted values. Only the existing PrivateToken GET path retains baseline 401/challenge semantics; regional JSON endpoints must not fabricate an unbound challenge for a missing holder key. In nonmatching profiles, these routes refuse without fallback. Original baseline routes outside regional operation remain unchanged.

These public route/body shapes are candidate semantics. The five executable schemas in this part cover policy, ARC RPC and holder nonce/proof only. Before M02/M03/M04 implement public consumers, Krish and Mihir must accept strict public envelope schemas/limits and corresponding fixtures in the shared contract. Do not infer that the table supplies a runtime HTTP validator.

## ARC private service

Mihir owns the Rust service/client helper; Krish owns gateway RPC consumption and shared replay. Pin an exact implementation revision in policy and record its source/license/draft match. ARC is privately verifiable with a joint operator trust model; its keys are separate from Type2/origin keys. Client issuance state and credential secrets live only in the actual client helper/container. The issuer/verifier must not generate presentations using a centrally held client secret.

### Bootstrap and issuer public parameters — M01 compatibility gate

Before the controller can hash/install an ARC policy, it needs the new service's immutable incarnation, implementation revision and public issuer parameters. Define a controller-only create-key/bootstrap operation, before ENABLE, returning `{run_id, service_incarnation, arc_implementation_revision, issuer_params_b64url, arc_key_id}`. The service generates a fresh ARC issuer key internally; no private issuer or client secret is returned. `arc_key_id` is SHA-256 of the exact canonical decoded public-parameter bytes. Those bytes must include the actual issuer public key and match the selected P-256 suite. The incarnation is a fresh random 16-byte identifier, hex encoded. Controller control channels remain private; this operation is not a gateway signing privilege or public endpoint.

**Exact public-parameter serialization and controller/helper transport are not invented by this candidate.** M01 must inspect the pinned library's `issuer_params`/public-key API and propose the canonical encoding, parsing/point checks, source revision, output-size bound and a real interoperability fixture. Krish and Mihir accept that proposal before freezing the bootstrap schema or enabling ARC consumers. This is a readiness gate along with verified tag extraction and client-side state handling.

After accepting bootstrap data through the trusted controller, the policy binds its key ID/revision. The issuer's public ARC directory must return the same canonical public parameters with policy digest/key ID/revision; clients compare them with the trusted installed policy, verify the hash, and use the pinned library to validate/decode parameters before credential finalization. A public directory is discovery, not a new trust-on-first-use authority. Do not generate a policy with fabricated key IDs or expose an issuer secret merely to make bootstrap work. A new service incarnation/key requires fencing and a fresh policy/run.

Two logical authenticated channels are required: `issue` and `verify`. Provision independent random 32-byte `arc_issue_rpc_key` and `arc_verify_rpc_key` through role-specific private files/pipes. The gateway receives only the verify key. An authenticated gateway verification caller must be unable to authorize signing. The private service holds both keys and its ARC key. TLS/local private deployment transport and startup addresses are infrastructure choices, but HMAC framing and limits below are mandatory. These MACs provide authenticity, not transport confidentiality; document plaintext internal links if used and never publish them.

Each bounded message is canonical JSON `{body,mac}` followed by exactly one newline. Reject extra keys, multiple objects, invalid UTF-8 and frames exceeding 65,536 bytes including newline. Connection read timeouts/concurrency are bounded by the existing five-second request lifecycle. Requests/replies use the schemas below, and channels reject the wrong operation regardless of MAC validity.

- Request MAC input: `regionalBytes(domains.arc_rpc, "request", operation, body)`.
- Response MAC input: `regionalBytes(domains.arc_rpc, "response", operation, body)`.
- MAC uses that operation's key with HMAC-SHA256. Verify in constant time after bounded structural parsing and before treating the content as trusted. Directions cannot be interchanged.
- `body` binds contract version, run ID, policy digest, random request ID and service incarnation. Issuance adds `grant_id` and blinded request. Verification adds presentation bytes. No caller-provided context/quota overrides.
- Replies echo those bindings and `request_digest = SHA256(canonicalJson(request_body))`. Success returns the credential response or canonical verified spend tag; errors use fixed schema labels. Check against the exact outstanding request and prepared service incarnation. Do not trust response fields merely because the MAC is valid.
- Replayed issuance requests must not cause a second signing; service grant use is atomic and terminal on uncertainty. Replayed verification requests may reverify, but never authorize access without the separate gateway atomic tag claim.
- Disconnect, malformed response, timeout, bad MAC, wrong binding/incarnation or service restart closes/refuses the dependent run; no automatic live resume under preserved credentials.

The wire tag is the protocol's verified group element serialized as **33-byte SEC1 compressed P-256**, prefix 02/03. The helper checks canonical encoding/point validity, not cryptographic presentation validity. The adapter must obtain the verified tag from an inspected library API or an explicitly reviewed minimal adapter. Do not guess proof offsets or use proof hashes. The current reference README's `verify -> Ok(())` does not establish that API availability. **M01 readiness remains pending exact revision/API inspection and a repeated-slot/re-randomization test.** If this fails, raise an interface request before integration rather than fabricating evidence.

`arcSpendId(policy, verifiedTag)` hashes a domain-separated canonical tuple including policy digest and canonical tag. This namespaces it by key, contexts, resource, generation and window. Its output stays private in the replay store and never enters public reports. Receiving a tag string does not prove it was verified; the authenticated exact-request-bound verifier reply and atomic gateway claim are both required.

The client helper's adapter surface is `create-request`, `finalize-credential`, and `present` through bounded private stdin/stdout frames. Serialize opaque library state only inside the owning client/container memory; no persistent secret files or public controller/report fields. The pinned library's state representation is not frozen here: M01 must propose its minimal opaque internal handles/serialization for counterpart review before consumer implementation. These operations never expose client credential secrets to the issuer/verifier.

## Holder-bound Type2

Use a fresh P-256 key pair per token, standard 91-byte canonical DER SPKI public key, and ECDSA with SHA-256. Signatures use fixed 64-byte IEEE P1363 `r || s`, **not DER**. Reject other curves/algorithms and noncanonical encodings. Private keys remain client-side; no device fingerprint or persistent device identifier.

Provision distinct fresh 32-byte gateway/controller secrets `holder_context_key` and `holder_nonce_key`. Share their current values across workers through private role configuration; never in policy/public manifests. These secrets and all generation keys rotate on reset. Do not reuse RPC secrets for this purpose.

Holder challenge redemption context is the 32-byte HMAC-SHA256 under the context key over `holderContextInput(policy, canonicalSPKI)`. The input binds domain, policy digest and SHA-256 of canonical public-key bytes. Construct challenges only for an active current window. No per-key registration table is required. During redemption reconstruct the expected challenge and verify the token's challenge digest, issuer signature and exact key binding. A signed token for a different public key or application profile is refused.

The nonce body contains version, run, policy digest, token hash, holder-key hash, issue/expiry times and 32 random bytes. It expires at `min(issued_ms + 10000, window_end_ms)` and is valid only for `issued_ms <= now < expires_ms`. MAC `holderNonceMacInput(body)` with the nonce key. Hash **decoded canonical 354-byte Type2 token bytes**, not its header/string spelling. The nonce endpoint is stateless but still requires bounded request/crypto work; callers can request a nonce without proving token validity, which grants no authorization.

Sign exactly `holderProofInput(...)`: domain, policy digest, decoded token hash, holder-key hash, fixed public POST redemption route, protected GET method/URL, empty protected-body SHA-256 and the complete signed nonce `{body,mac}`. JSON proof transport fields do not become an additional application body. The policy/route encoding in the Python fixture is authoritative. There is no arbitrary URL/query/body canonicalization in this version.

On redemption, validate framing/profile/window, token authenticity, expected holder-bound challenge, nonce MAC and binding, SPKI and signature **before spending**. Carry authenticated nonce expiry to the atomic regional claim. Do not consume either token or nonce for invalid proof. A valid proof needs only the existing token single-spend identity (independent of signature bytes), not a nonce-consumption table. Concurrent valid proofs still compete for one token claim. Changing a signature's bytes cannot yield a new token identity.

Nonce checks and cryptographic operations are runtime work, not supplied by the structural helpers. For example, a structurally valid all-zero signature is not a valid authorization. A stolen complete still-valid signed request can win its exact first-use race. Client compromise or cooperating key holders can sign; this is token-only theft protection, not universal theft prevention or standard OAuth DPoP compliance. Per-token contexts also have timing/caching privacy costs.

## Evidence and integration gates

Existing report schemas 1–3 and scenarios remain immutable. Do not add regional fields/scenarios to saved v3 reports or reuse old scenario names to suggest new guarantees. K04 will add a separately versioned regional evidence format before M05 writes live product results. M01/M02 integration does not require pretending that future reporting is ready.

Public evidence uses aggregate decisions, issuance counts, cross-worker attempts, independent origin received/served totals, delivery uncertainty and timings. No vouchers, token/proof data, public holder keys, spend tags, actor authorization IDs or per-request history. The UI controls labelled lab clients and is not initially a browser wallet. Local action endpoints require fixed commands, Host/Origin/CSRF protection and no arbitrary Docker/filesystem/URL access. Operator reset/experiment controls are not ordinary client entitlement operations.

K01 checks cover schema parity, exact Python/Node encoding and MAC vectors, window/nonce boundaries, response swapping, canonical key/tag validation, and real P-256 signing interoperability. They do not prove ARC cryptography, atomic quotas, runtime HTTP routes, private channel authentication, reset safety or the UI. Counterpart acceptance and those runtime checks remain necessary.

## Counterpart handoff

Mihir can start pinned ARC feasibility and dependency/build work immediately. Review this candidate and the fixtures, especially bootstrap/public parameters, tag extraction and opaque client state, before implementing consumer interfaces. Return exact incompatibilities; Krish owns shared changes. Once accepted, implement M01/M02 and coordinate K02, then product/holder consumers. No main merge or baseline runtime enablement occurs merely because this candidate is pushed.

Checks:

```powershell
node scripts/generate-regional-schemas.mjs --check
python scripts/derive-regional-fixture.py --check
node --test src/services/gateway/test/regional-contracts.test.ts
npm.cmd run check:g0
```

## Sources

- [Privacy Pass authentication, RFC 9577](https://www.rfc-editor.org/rfc/rfc9577.html)
- [Privacy Pass issuance, RFC 9578](https://www.rfc-editor.org/rfc/rfc9578.html)
- [ARC protocol draft, including verified-tag replay checks](https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-arc-protocol)
- [ARC reference implementation and current API stability](https://github.com/cloudflareresearch/arc)
- [DPoP security considerations, used as design background](https://www.rfc-editor.org/rfc/rfc9449.html#section-11)

ARC is work in progress. These sources do not standardize TokenForge's regional transport or holder-binding profile.
