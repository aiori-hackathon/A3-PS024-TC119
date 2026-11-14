# Regional gateway integration

## K02-B: authenticated ARC verification and protected-request pipeline

The gateway now has a concrete private TCP verifier client, native regional Redis pool opener, shared request pipeline and bounded JSON POST support in the existing TLS adapter. These components can be prepared by the gateway lifecycle host; the old controller/Compose startup still selects the baseline path until regional configuration is wired explicitly. This is not a claim that Mihir's live Rust service or the regional application is already deployed.

### Shared bootstrap and public messages

`src/contracts/lib/regional-wire.ts` implements canonical raw decoding, HMAC helpers, ARC bootstrap validation and public request/response checks. The schema generator now includes:

- `regional-arc-bootstrap-v1.json`
- `regional-public-request-v1.json`
- `regional-public-response-v1.json`

Public schema `{route, body}` objects are **validator wrappers**. Only `body` is sent over HTTP. The route is chosen by the server from the exact method/path; it is not a caller-controlled alternate routing field. Public JSON bytes must equal canonical sorted-key JSON with no trailing newline. RPC frames use canonical `{body,mac}` plus exactly one newline. Raw-byte equality after fatal UTF-8 decoding rejects duplicate keys, ambiguous re-serialization and trailing objects. Size is bounded before parsing.

Mihir's inspected P256 adapter supplies 99 public parameter bytes: X0 commitment, X1, X2, each a canonical nonidentity compressed SEC1 point. Bootstrap validates all three points, exact unpadded encoding, SHA-256 key ID, run and trusted expected implementation revision. The controller must pin the **actual corrected repository source commit** for its built service, not merely the original upstream dependency revision. Key IDs are public-key identities, not binary attestation. Bootstrap/incarnation arrive through the trusted controller channel; the gateway never trusts an unsolicited public directory as its authority.

Enrollment schemas enforce one ARC request/response or five Type2 requests/responses. Public payloads bind installed policy and selected profile. Type2 request/response sizes retain RFC 9578 values. ARC directory checks pin parameter bytes/key/revision to policy. Holder challenge responses check RFC challenge framing and the pinned Type2 public key; the holder MAC context itself is server-authenticated, not a client identity.

### ARC RPC client

Prepare `ArcVerifierClient` with installed policy, trusted bootstrap, a private startup endpoint, copied 32-byte **verification-only** MAC key and at most one/two concurrent calls. This client cannot issue credentials. The endpoint is immutable private configuration; no request supplies a destination.

Requests use the accepted verify schema, a random request ID, exact service incarnation and policy digest. The response must authenticate its direction/operation/body and echo the exact request digest and bindings. Only then is a canonical verified tag converted into a private receipt. `consume(receipt)` is instance-owned and single-use, deriving the policy-scoped replay ID itself. The public request cannot substitute a tag or manufacture a receipt.

Each call has one 1,500 ms total RPC cap, a 1,000 ms connect cap and the enclosing request's remaining absolute deadline. It uses one socket/frame, bounds reads to 65,536 bytes, waits for local socket closure and never reconnects/retries. Cancellation destroys the request's socket and suppresses its result without treating a disconnected client as a server fault. Over-capacity calls return busy without queueing. Bad MAC/framing/binding, unexpected incarnation, unavailable service or uncertain transport closes the dependent client/run; ordinary client-caused proof rejection must remain a non-consuming refusal. The Node fixture peer tests transport only; it is not the real ARC Rust verifier.

Authenticated `invalid-input`, `invalid-proof` and `window-closed` replies are ordinary refusals. Arbitrary opaque presentation bytes can cause a decoder refusal, so `invalid-input` must not let a public attacker terminate the whole run. Authenticated `unavailable`, wrong installed policy or an operation-inappropriate result remains an infrastructure/configuration fault.

The MAC authenticates internal data but does not encrypt private TCP traffic. Retain the isolated-network/trusted-host assumptions or provide protected private transport before a broader deployment. Never publish the verifier listener or its MAC key.

### Single authorization pipeline

`RegionalCoordinator` reuses `FlowAdmission`, `WorkerLease` and `FixedOrigin`. It requires matching prepared bindings and a ready regional replay store. ARC mode accepts only its exact JSON redemption POST, with no bearer fallback.

Processing order is bounded framing/policy validation, authoritative time snapshot, proof verification, fresh authoritative snapshot, one receipt consumption, atomic replay claim, liveness recheck and one fixed-origin send. Invalid proof never invokes the claim. An uncertain claim/response never triggers retry/refund. The transport's cancellation/deadline is carried into the flow permit and the origin's native send check. Admission capacity stays held through response/cleanup. Unsafe dependencies close the run, not an alternative authorization mode.

The existing `HttpsGateway` accepts POST bodies only when a prepared regional coordinator explicitly declares the fixed 64 KiB body capability. It requires bounded canonical Content-Length, rejects transfer encoding and waits for complete body settlement before dispatch. Existing TLS1.3/SNI/HTTP1.1, header/socket limits, absolute TCP-accept deadlines, one-request-per-connection and baseline no-body behavior remain intact. There is no request or environment flag that turns regional authorization on.

`openRegionalRedisReplayStore` uses the same pinned ioredis/no-offline-queue/no-retry transport as the baseline, but prepares the regional store and requires its separate account/state. Use the bootstrap order in [REGIONAL_REPLAY.md](REGIONAL_REPLAY.md).

### Remaining deployment dependencies

Mihir owns the actual Rust RPC/bootstrap server and client helper, admission, controller and Compose wiring. The inspected adapter exposes the required verified tag; it is not yet a network service. K04 will complete runtime selection/product evidence after both sides agree and interoperate. Do not promote a fixture-backed RPC response or a local origin stub into deployed ARC evidence.

K02-B tests cover actual loopback framed sockets/HMACs, stale/swapped replies, opaque receipts, canonical public requests, preparation bindings, verify-before-claim order, replay refusal and bounded TLS POST parsing. Baseline TLS tests continue to exercise the unchanged legacy mode.

## K03: holder-bound Type2 and prepared gateway API

`HolderVerifier.prepare(manifest, policy, contextKey, nonceKey)` imports only the issuer's public RSA key and copies two distinct 32-byte gateway MAC keys before awaiting preparation. Keys stay private and are cleared on terminal close. The verifier bounds active proof work to the selected worker profile and waits for active crypto to settle during close.

The challenge endpoint creates the standard Type2 challenge using a 32-byte HMAC of policy and the canonical ephemeral holder public key. The nonce endpoint returns a stateless MAC-authenticated body binding run, policy, decoded token hash, holder-key hash, issue/expiry times and fresh randomness. It exposes neither private MAC key. Client code uses its own private P-256 key and the public challenge/nonce responses; client code must never receive gateway context/nonce keys.

The redemption verifier checks canonical encodings, policy, nonce binding/MAC and IEEE-P1363 P-256 signature, then reuses `TokenVerifier.verifySignature`. Its new `consumeSignatureContext` method consumes that instance's opaque RSA receipt against an **internally calculated** holder-bound challenge digest and returns the owned token's spend identity/hash. Public JSON cannot supply an expected digest. The nonce's hash and the RSA receipt must refer to the same token bytes. Baseline `checkContext(receipt, epoch)` behavior remains unchanged.

Only a fully verified holder request receives an opaque single-use regional receipt. Its candidate carries authenticated nonce expiry to Redis's final atomic check. Bad signatures, stolen token bytes signed with the attacker's own key, altered nonce/request/key/token, stale nonce and invalid contexts do not invoke the claim. Fresh nonces cannot revive an already-spent token. Complete valid signed requests can still race their first use; compromised clients/private-key sharing remain outside this profile's token-only theft protection.

### Explicit activation API

The gateway build includes `dist/regional-gateway.mjs`, exporting `prepareRegionalGateway(manifest, regionalPolicy, lease, options)`. It is an inert library until called with trusted private configuration. `options` contains a fixed Redis endpoint/credential, TLS certificate/key and one matching authentication variant:

- ARC: `{profile:"arc", bootstrap, endpoint, verify_key}`.
- Holder: `{profile:"type2-holder", context_key, nonce_key}`.

The factory validates bindings, prepares the profile verifier and native restricted Redis pool, connects the shared coordinator and existing fixed-origin transport, and creates the TLS adapter. It returns `{gateway, coordinator, replay}`. The caller must already have completed fenced fresh-generation provisioning and must install the existing all-worker original-expiry lease grants before calling `gateway.listen`. The factory never enables a lease, chooses an upstream from a request, resets Redis or publishes a listener on import.

The production `serve` entry point now accepts the optional private regional startup branch described below and uses the existing worker lifecycle. The factory is not a replacement for the reset barrier. Controller/Compose provisioning, admission and the product UI still require integration by their service owner.

### Verified native integration scope

`npm.cmd run test:regional-integration --prefix src/services/gateway` runs one disposable network-isolated Redis and a Node test container with real TLS1.3 requests, genuine blind issuance, actual holder endpoints and two separately prepared gateway/pool instances sharing Redis. The issuer is a test-local real cryptographic API; this is **not** Mihir's enrolled/deployed issuer/controller flow or two production OS worker processes.

The client requests its challenge and nonce over TLS and signs using only its own private key. Checks require: token-only attacker refusal; bad MAC/wrong route creating no spend key or origin arrival; subsequent owner success; ordinary and fresh-nonce replay refusal; success on the second prepared worker; and 20 valid duplicate requests producing exactly one additional independently counted HTTP origin arrival. Other raced refusals may be replay or bounded overload; they must not produce additional arrivals. Output is aggregate-only.

The same test executes the regional Lua through the actual restricted account and verifies both direct and administrator-loaded-script policy writes are denied. It exposed a Redis ACL integration issue that DRYRUN alone missed: EVALSHA's declared keys require read/write admission. The fix is a command-only EVALSHA selector over the declared keys, while real inner commands retain read-only policy permissions. No policy-write permission is added to HSET/SET. [Redis ACL selectors](https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/)

The final runtime image contains only production bundles/dependencies. Its explicit payload allowlist includes the regional library; test helpers/credentials exist only in the isolated test build target or private stdin. There is no claim of full regional deployment until the remaining controller/service/client/UI work is connected and checked.

## Runtime selection and comparison profiles

The existing private stdin object `{listen_host,redis,tls}` remains valid and produces the unchanged baseline behavior. An optional `regional:{policy,auth}` selects exactly one immutable regional policy before workers fork. The public `PREPARE_RUN` payload remains unchanged, including empty gateway `role_config`. Public requests, headers and environment variables cannot select another profile. A policy/manifest/profile mismatch refuses preparation; it never falls back.

`auth` is a strict JSON-safe object with exactly these fields (keys are 64-character lowercase hex in stdin/IPC):

| Profile | Private auth fields | Public resource operation |
| --- | --- | --- |
| `arc` | `profile`, `bootstrap`, `endpoint:{host,port}`, `verify_key` | Canonical POST `/regional/arc/redeem` |
| `type2-holder` | `profile`, `context_key`, `nonce_key` (distinct keys) | Existing holder challenge/nonce/redeem POST routes |
| `type2-bearer` | `profile` | GET `/resource`, standard PrivateToken Authorization |
| `ip` | `profile`, `source_key` | GET `/resource`, TCP-source budget |

The library factory takes the same authentication choices with binary `Uint8Array` keys instead of hex strings; it also accepts an optional private `SourceObservation`. Startup values are copied before asynchronous preparation. Neither status nor report serializes startup objects. Operators must supply fresh per-run keys, complete `initializeRegionalStore` while fenced and use its restricted-account ACL, then retain the existing PREPARE/READY/ENABLE/HEARTBEAT/FENCE sequence. Both workers use the same policy and private keys. Fresh processes and fresh generation state remain mandatory for resets; do not run baseline fresh-store readiness after regional provisioning.

The ordinary Type2 challenge is `regionalType2Challenge(regionalContext(policy))`; a baseline epoch challenge cannot authorize this profile. Standard bearer tokens remain transferable: a thief who redeems first can win. The separate holder profile mitigates token-only theft, not theft of the private signing key or a complete valid signed request.

IP comparison uses a run-keyed, policy-scoped HMAC of the actual accepted TCP source. It normalizes mapped IPv4 addresses and ignores Forwarded/X-Forwarded-For values. No raw address or HMAC identifier enters reports. With the demo proxy this intentionally creates one shared budget for the five admitted clients: 25 accepted uses per fixed window. It is **not** five requests per person. The Lua claim validates method/route beforehand, atomically increments an exact-expiry counter only through 25, then returns 429. Invalid routes do not consume budget. Confirmed claims are never refunded after uncertain upstream delivery. Missing/corrupt state fences the generation and cannot recreate an allowance.

### Aggregate evidence and its limits

REPORT retains the existing version/schema and allowed fields. Regional runs add existing allowed counters `claims_successful`, `replays_rejected`, `requests_rejected`, `queue_rejected`, `transport_failures` inside `counters`; baseline runs omit these additions. Claims count confirmed Redis consumption even if the request deadline is lost immediately afterward. Rejections count attempted HTTP refusal responses; queue refusals are a subset. `transport_failures` counts an unavailable claim result, not every possible network failure. Redis `rpc_outcomes` conservatively records failed claim outcomes as uncertain, with actual timer expirations counted separately. No source tags, proof bodies or keys are exported. The profile/policy identity comes from the controller's own frozen startup policy and the ordinary run/config envelope, not a client declaration.

`verification_ms` samples successful complete profile verification (including holder proof or ARC RPC as applicable), and counts non-success separately as failures. `authorization_ms` samples successful admission-through-claim only, excluding origin and response delivery; non-authorized requests count as failures. Challenge/nonce control requests do not produce a successful authorization sample. `snapshot_rpc_ms`/`claim_rpc_ms` sample completed RPCs, including ordinary refusals; failed RPCs contribute failure counts. Compare successful timings with their denominators, refusal counts and profile costs rather than treating unlike verification work as identical crypto benchmarks.

Source observation now includes regional resource/redeem operations as well as the original Authorization observations. `origin_counts_available` stays false at the gateway. The controller must obtain settled before/after counters from the independent origin, check run/incarnation/generation and attribute them to each scenario phase. A theft claim requires attack-phase zero arrivals followed by owner-phase success; one total arrival alone cannot distinguish the thief winning. Missing admission, origin or integration evidence remains INCONCLUSIVE. Do not reuse baseline saved-report schemas to assert unimplemented regional scenarios.

### Focused native validation

The isolated integration command now checks both the earlier two-instance flow and three separate production `serve.mjs` runs. Each production run proves two distinct child OS workers, the shared TLS listener, restricted Redis enforcement, existing control responses and confirmed worker exit after FENCE. Tests cover IP 25/26 and concurrent exhaustion despite forged forwarding headers; Type2 challenge and copied-token races; holder token theft followed by owner success and cross-worker replay; wrong-profile routing; and state-loss fencing without live repair. Actual HTTP origin counters independently bound the accepted arrivals.

These tests use genuine cryptographic blind issuance through a test-local issuer API and a counted private test origin. They do not prove the deployed voucher/entitlement cap, actual Rust service/client interoperability, portal controls, direct-origin network isolation, complete ARC quota/copy scenes, renewal or end-to-end product deployment. Those require the real controller/issuer/ARC/helper/Compose integrations and focused follow-up validation.

### Consumer compatibility gate

Regional JSON responses now use the shared canonical writer, including nested holder nonce bodies. This preserves the existing schema, status codes and HTTP headers while making actual challenge/nonce bytes acceptable to the regional client's canonical decoder. The native holder transport check validates those exact response bytes before using them.

After the regional issuer/client and Rust service sources are integrated, run:

```powershell
node scripts/check-regional-consumers.mjs
```

This command refuses missing/uncommitted ARC prerequisites, builds the pinned ARC image with its committed source revision, and runs two required Linux consumer tests with zero skips. It uses isolated Redis and an unprivileged read-only test container without published ports, host mounts or external network access. Test assertions are captured rather than printed because failures can contain ephemeral credentials/proofs. Build diagnostics remain visible. Test files/dependencies belong only to this test image, not the production images.

The ARC test exercises the actual Rust service, helper, issuer admission and Node client through its explicitly labelled substitute gateway. The holder test exercises the actual Node client, issuer admission, holder gateway, restricted Redis and independently counted test origin: five-token acquisition, failed theft without consumption, owner success, replay refusal, a duplicate race and exhaustion. It would reject the previous noncanonical gateway responses. Neither test proves the full deployed ARC gateway/controller/UI path or shutdown safety.

CI enables this gate when the ARC service implementation exists in the checked-out branch. On a branch that has not integrated those files, it emits an explicit pending-integration notice; that absence is not regional acceptance. The runner itself never reports success for missing prerequisites or skipped tests. The ordinary gateway startup regression tests also run under `check:g0`.
