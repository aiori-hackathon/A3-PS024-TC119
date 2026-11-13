# ARC feasibility component

This package exercises real blind issuance and presentation with the selected upstream implementation. Its status is **isolated feasibility, integration_ready=false**. Live issuer/verifier RPC, client-helper transport and authoritative admission depend on accepted K01 contracts and resolution of the verifier findings below.

## Reproducible inputs

| Input | Pin |
|---|---|
| ARC source | `cloudflareresearch/arc` revision `4f023d349a552d019ee0d8d7f73921da8d035165` |
| Upstream package | `arc` 0.1.0, Apache-2.0 |
| Specification | `draft-ietf-privacypass-arc-crypto-01`, work in progress, expired September 3, 2026 |
| Selected suite | P256, SHA-256, upstream context `ARCV1-P256` |
| Compiler | Rust 1.89.0 |
| Dependencies | Service-local `Cargo.lock`, including the upstream pinned Sigma dependency |
| Build/runtime images | Exact digests in `Dockerfile` |

The upstream source and specification describe the protocol and API. [Pinned source](https://github.com/cloudflareresearch/arc/tree/4f023d349a552d019ee0d8d7f73921da8d035165), [draft-01](https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-arc-crypto-01), [upstream license](https://github.com/cloudflareresearch/arc/blob/4f023d349a552d019ee0d8d7f73921da8d035165/LICENSE).

## Run the feasibility checks

From the repository root with Linux-container Docker running:

```sh
docker build -f src/services/arc/Dockerfile -t tokenforge-arc-feasibility:local .
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 128m --pids-limit 32 tokenforge-arc-feasibility:local
```

The verification build runs the adapter checks and the pinned upstream P256 protocol/vector tests. The runtime image contains the aggregate-only feasibility executable. The executable performs issuance, verifies five presentations and reports request/response/presentation lengths. The five-use value and context strings are local test fixtures. Production values await K01.

For a native Rust 1.89.0 toolchain:

```sh
cargo test --locked --manifest-path src/services/arc/Cargo.toml
cargo run --locked --manifest-path src/services/arc/Cargo.toml --bin arc-feasibility
```

On this Windows host, the installed GNU toolchain works with MSYS2 UCRT64 tools first in the command's PATH:

```powershell
$env:Path = 'C:\msys64\ucrt64\bin;C:\Users\Mihir\.cargo\bin;' + $env:Path
cargo +stable-x86_64-pc-windows-gnu test --locked --manifest-path src/services/arc/Cargo.toml
```

Verify that this override still selects Rust 1.89.0. The older 32-bit MinGW tools caused a linker failure on the inspected host.

## Client boundary and evidence

`PendingIssuance` creates and retains the client secret. The issuer receives serialized blinded requests. Finalization consumes pending client state and returns a client-owned wallet. The adapter provides no credential or secret-key export. Presentation state is an upstream object that the client caller must retain privately. Tests construct two wallet states and confirm that fresh randomized presentations of the same slot have different proof bytes and matching protocol-tag fields under the pinned P256 encoding.

The public upstream verifier returns `Result<(), ArcError>`. Its presentation tag remains private. A reviewed verified-tag API is required for the live verifier reply. K01 must also bind that reply to the accepted proof, policy, key and generation. K02 supplies the authoritative shared-store claim.

## Integration findings

A private negative test confirmed that the pinned upstream verifier accepts a presentation constructed without credential issuance using identity credential elements. The P256 adapter applies an exact parse-reserialize equality restriction that rejects the reproduced padded wire. Upstream object verification remains an unresolved cryptographic finding. Astra reviewed this containment and requested coordinated upstream/K01 remediation before integration readiness.

The upstream issuance API accepts a blinded request without an expected request-context argument. K01 candidate `68428be` specifies fresh issuer keys for every window/run and fenced renewal to address credentials prebound to future contexts. Runtime enforcement remains pending. Verifier policy must select quota, key and both contexts, and its replay scope must preserve the same admitted entitlement across aliases and renewal.

Detailed findings and the private reproducer location are in the local compatibility request for Krish. The existing Type2 deployment remains the working integrated baseline while regional contracts are prepared.
