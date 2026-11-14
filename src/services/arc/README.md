# ARC P256 component

The locally corrected P256/N=5 adapter supplies an isolated issuer/verifier service and a client-owned cryptographic helper. `Issuer::verify_and_tag` returns the verified 33-byte protocol tag from the same parsed presentation. The reproduced upstream identity forgery is rejected by decoding and direct verification. Process tests exercise blind issuance, finalization and randomized presentations through authenticated TCP and private helper pipes. Gateway replay claims and origin-backed authorization require the surrounding lab integration. The separate feasibility executable reports `integration_ready=false`.

## Pinned inputs

| Input | Pin |
|---|---|
| Upstream ARC | `cloudflareresearch/arc` revision `4f023d349a552d019ee0d8d7f73921da8d035165` |
| Vendored package | ARC 0.1.0, Apache-2.0, upstream notices retained |
| Local correction | `tf-arc-p256-1`, auditable patch and SHA-256 in `vendor/provenance.json` |
| Specification | `draft-ietf-privacypass-arc-crypto-01`, work in progress, expired September 3, 2026 |
| Supported service suite | P256/SHA-256, context `ARCV1-P256`, quota five |
| Compiler | Rust 1.89.0 |
| Sigma dependency | `f6a1737673ed3b76c66659a17e7ec4174fcdbe7a` |
| Images | Exact digests in `Dockerfile` |

The upstream source, license and pinned draft describe the implementation and input rules. [Pinned source](https://github.com/cloudflareresearch/arc/tree/4f023d349a552d019ee0d8d7f73921da8d035165), [draft-01](https://www.ietf.org/archive/id/draft-ietf-privacypass-arc-crypto-01.html), [upstream license](https://github.com/cloudflareresearch/arc/blob/4f023d349a552d019ee0d8d7f73921da8d035165/LICENSE).

The production policy's 40-hex implementation revision must identify the repository commit containing this corrected adapter. Resolve that source commit when building/deploying and carry it through trusted bootstrap. The descriptive adapter name and original upstream revision are provenance metadata. Public parameters/key IDs cannot attest the implementation version by themselves.

## Local correction and verified tag

The pinned draft's P256 element decoding rejects infinity/identity, and its presentation verification returns validity and the tag. The vendored correction enforces checked group-element decoding in public parameters, requests, responses, credentials, client state and presentations. Direct verification also checks every presentation point, range shape and context base. `verify_and_tag` returns the tag only after verification succeeds. Proof equations and transcript construction retain the upstream implementation. [Draft P256 input rules](https://www.ietf.org/archive/id/draft-ietf-privacypass-arc-crypto-01.html#section-6.1), [draft verification](https://www.ietf.org/archive/id/draft-ietf-privacypass-arc-crypto-01.html#section-4.3.3).

Astra reviewed the actual correction and adapter with no blocking code finding. This is an experimental locally corrected implementation with targeted regressions. Independent cryptographic audit and upstream review remain pending.

The root adapter accepts only N=5 and checks exact parse/reserialize equality. Fresh issuer parameters are validated before publication. Every returned tag is a 33-byte compressed P256 point with prefix 02/03. Tests recreate five slots with independent proof randomness, compare equal verified tags for the same slot and check different tags across slots. Production code uses the verified-tag API.

The original unpatched dependency exists only in dev-dependencies to preserve the confirmed negative regression. Its synthetic unissued credential/presentation is accepted by upstream and rejected by the corrected implementation, including the in-memory path. Release code uses the vendored dependency.

## Public parameters and client boundary

Canonical public parameters are 99 bytes, ordered X0 commitment, X1, X2, each a nonidentity 33-byte compressed SEC1 P256 point. Canonical unpadded base64url has 132 characters. The key ID is lowercase hex SHA-256 of those exact 99 bytes. `fixtures/public-parameters.json` contains public-only draft-vector data. The Node check independently validates points, encoding and digest against the unchanged upstream vector; the Rust vector test validates the same serialization.

`PendingIssuance` creates the client secret and consumes it on finalization. A wallet retains the credential in the client. Its returned upstream `State<P256>` can serialize client secrets and must remain behind the owning client helper's memory/opaque handles. Bootstrap exposes public parameters. The issuer/verifier receives blinded requests and presentations through independent authenticated channels.

At N=5, the measured request is 226 bytes, response 454 bytes and presentation 744 bytes. These fit K01's existing bounded blob and frame sizes. Fresh keys per run/window and server-selected contexts remain required by the surrounding regional policy.

## Run checks

From the repository root with Linux-container Docker running,

```sh
docker build --build-arg TF_ARC_SOURCE_REVISION=$(git rev-parse HEAD) -f src/services/arc/Dockerfile -t tokenforge-arc-feasibility:local .
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 128m --pids-limit 32 tokenforge-arc-feasibility:local
```

The verification stage runs adapter/process regressions, corrected vendor unit/protocol/vector tests and unmodified pinned upstream protocol/vector tests. The runtime image contains `arc-service`, `arc-client-helper`, `arc-feasibility` and their system runtime.

With native Rust 1.89.0 and Node 24,

```sh
cargo test --locked --manifest-path src/services/arc/Cargo.toml
cargo test --locked --manifest-path src/services/arc/vendor/arc/Cargo.toml --features suite_p256
node --test src/services/arc/tests/public-parameters.test.mjs
cargo run --locked --manifest-path src/services/arc/Cargo.toml --bin arc-feasibility
```

On the inspected Windows host, the GNU toolchain requires MSYS2 UCRT64 tools before the older MinGW installation,

```powershell
$env:Path = 'C:\msys64\ucrt64\bin;C:\Users\Mihir\.cargo\bin;' + $env:Path
cargo +stable-x86_64-pc-windows-gnu test --locked --manifest-path src/services/arc/Cargo.toml
```

Verify that this override selects Rust 1.89.0. The compatibility scope is P256 with quota five. Regional authorization evidence still requires the authenticated exact-request-bound verifier reply, authoritative shared-store claim, current lease and independent origin counters.

## Private process integration

Every control/helper frame uses sorted-key canonical JSON followed by one newline. Bounds and canonical rules come directly from the shared contracts. The owning controller/client retains the pipes. Pipe closure terminates the component. Keep pipe contents out of process logs, reports and UI output.

Start `/usr/local/bin/arc-service` with stdin/stdout piped. Send the initial control frame with all of these fields.

```json
{"implementation_revision":"<40 lowercase hex source revision>","issue_key":"<64 lowercase hex>","issue_listen":"0.0.0.0:7101","operation":"bootstrap","run_id":"<32 lowercase hex>","verify_key":"<independent 64 lowercase hex>","verify_listen":"0.0.0.0:7102"}
```

The response is the exact shared `ArcBootstrap` object, including fresh incarnation, 99-byte public parameters, their SHA-256 key ID and compiled implementation revision. `TF_ARC_SOURCE_REVISION` supplies the source identity at build time. Native builds resolve Git HEAD when the variable is absent. Startup requires the supplied revision to equal the compiled revision. Build release artifacts from the committed source revision selected for the run.

Send `{"operation":"install-policy","policy":<shared RegionalPolicy>}` once. Success returns `{"policy_digest":"<digest>","status":"installed"}`. The service validates shared ARC policy structure, window length and bootstrap run/key/revision bindings. The controller performs baseline-manifest validation before installation.

Send `{"lease_expires_ms":<absolute epoch milliseconds>,"lease_sequence":0,"operation":"enable"}` after the window opens. Success returns `{"status":"enabled"}`. Renew with `heartbeat`, the next sequence, and the original bounded absolute expiry from the controller. Success returns `{"status":"renewed"}`. The maximum lease comes from the baseline's `gateway_common.controller_lease_ms`. Expiry uses both monotonic and wall clocks. Observed clock regression and expired leases permanently fence the generation. Send `{"operation":"fence"}` to close it explicitly. `status` returns a sanitized lifecycle label. Renewals after fencing are refused. Control refusals use `{"code":"<fixed label>","status":"refused"}`.

Issue and verify TCP listeners accept their corresponding shared request schema and operation key. Each connection carries one request and one response, each bounded to the shared frame size and 1,500 ms total RPC deadline. Responses start immediately after a complete newline frame arrives. Each listener admits at most four active connections. The service serializes cryptographic work and grant reservations. Five unique grant reservations fit the run budget. Reservation occurs before signing, and failure keeps that reservation consumed. Every successful response carries the exact request digest and bindings. Invalid authentication receives a closed connection. Dependency failures require the controller/gateway to close the dependent run. These private TCP links use plaintext within the isolated deployment network, with HMAC authentication.

Start `/usr/local/bin/arc-client-helper` separately inside each owning client. It supports one pending issuance and one finalized wallet. All client secrets remain in helper memory. Operations and successful replies follow this table.

| Operation fields | Reply fields |
|---|---|
| `operation="create-request"`, `policy`, `issuer_params_b64url` | `status="created"`, `pending_handle`, `blinded_request_b64url` |
| `operation="finalize-credential"`, `pending_handle`, `credential_response_b64url` | `status="finalized"`, `wallet_handle` |
| `operation="present"`, `wallet_handle`, optional `slot` | `status="presented"`, `presentation_b64url` |

Handles contain 16 fresh random bytes encoded lowercase hex. Finalization consumes its pending handle before processing the response. Public parameters are validated and hashed against the trusted installed policy before client request creation. Every operation enforces the selected window. Presentations use shared policy-derived contexts and quota. Omitting `slot` advances a local five-use estimate. Explicit slots 0–4 recreate that credential's selected spend with fresh proof randomness for controlled copy/rollback/race scenes. Authoritative gateway tag claims decide acceptance. Repeated-slot support exports only the presentation through the owning client's private pipe. Refusals return fixed labels. Process tests validate MAC fixture parity, separate channel keys, terminal grant use, concurrent duplicate signing, five-grant bounds, lease expiry and fencing.
