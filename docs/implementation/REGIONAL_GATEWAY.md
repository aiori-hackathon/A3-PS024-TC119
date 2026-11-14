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
