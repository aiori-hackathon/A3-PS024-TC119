# Gateway

G0 establishes the contract/library/build path. Gateway components now cover binary-token verification, bounded Authorization parsing and fixed challenge/error response construction. **No HTTP listener, Redis claim script or protected forwarding exists yet.**

`TokenVerifier.prepare(manifest)` copies and validates trusted configuration and imports only the issuer public key. `verify(wire, expectedEpoch)` checks exact Type 2 length, full key ID, public signature and configured challenge digest. It owns copies of incoming byte views before awaiting crypto. Rejections use fixed labels without reflecting credentials.

Success returns a `claim-candidate` with spend ID and epoch, not an authorization decision. The HTTP adapter must obtain `expectedEpoch` from a safe authoritative snapshot; the later atomic Redis claim must recheck current time/context before any forwarding. Repeating this component alone does not prevent replay. Do not log returned spend IDs or raw token data.

`parseAuthorization(request.rawHeaders)` accepts the complete flat raw header list, not Node's normalized header map. It bounds field count/Latin-1 octets before parsing, refuses duplicate Authorization fields and duplicate parameter names, processes quoted strings/escapes, and ignores syntactically valid unknown parameters. It tolerates at most eight empty list members. Decoded tokens must have canonical base64url and exactly the Type 2 wire length. An absent/unsupported authentication scheme requests a PrivateToken challenge; parsing a credential does not validate its signature.

`GatewayResponses.prepare(manifest).rejection(reason, freshSnapshotReply)` returns fixed JSON, `no-store` and byte-accurate content length. Every 401 requires a checked snapshot matching the configured run/key/digest/bounds and includes the shared challenge/public key. Missing/unsafe snapshot data produces 503 without a challenge. A 405 includes `Allow: GET`. Nothing reflects submitted credentials or creates clearance cookies. Before using this formatter, the future HTTP adapter must obtain a new authoritative snapshot and check its active supervision lease; the formatter does not establish freshness or run state itself.

The enclosing transport still needs its TLS/header deadlines, Node framing limits, route/method/body restrictions and admission control. These pure helpers do not enforce those runtime controls. Protocol references: [RFC 9577](https://www.rfc-editor.org/rfc/rfc9577.html) and [RFC 9110 authentication](https://www.rfc-editor.org/rfc/rfc9110.html#section-11).

From repository root (PowerShell uses `npm.cmd`; other shells use `npm`):

```powershell
npm.cmd ci --prefix src/services/gateway --ignore-scripts
npm.cmd run typecheck --prefix src/services/gateway
npm.cmd test --prefix src/services/gateway
npm.cmd run build --prefix src/services/gateway
npm.cmd run test:bundle --prefix src/services/gateway
npm.cmd audit --prefix src/services/gateway
```

Build outputs are `dist/bootstrap.mjs` (public metadata smoke entry, exits), `dist/token-verifier.mjs` and `dist/http-auth.mjs`. Tests include real signed wrong-context tokens, malformed/tampered inputs, duplicate/ambiguous authentication, quoted parameters, header budgets, challenge-bearing 401s, unavailable snapshots, configuration/input isolation and compiled-bundle compatibility. Public fixtures and fresh ephemeral test keys are never printed or persisted as live credentials.

Docker: `docker build -f src/services/gateway/Dockerfile -t tokenforge-g0:local .` from **root**, then run without network/privileges. The image still uses the metadata smoke entry; it is not a serving gateway. The root `check:g0` command runs both consumers and the additional verifier tests.

See `docs/security/DEPENDENCY_REVIEW.md` for the scoped patched transitive dependency and byte-buffer integration constraints. Service-local package lock is authoritative. No root workspace or another owner's private code import.
