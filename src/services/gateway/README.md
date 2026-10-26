# Gateway

G0 establishes the contract/library/build path. Gateway components now cover binary-token verification, bounded Authorization parsing, fixed challenge/error responses and tested Redis snapshot/claim scripts. **No HTTP listener, runtime Redis adapter or protected forwarding exists yet.**

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

Build outputs are `dist/bootstrap.mjs` (public metadata smoke entry, exits), `dist/token-verifier.mjs`, `dist/http-auth.mjs` and `dist/replay-scripts.mjs`. Tests include real signed wrong-context tokens, malformed/tampered inputs, duplicate/ambiguous authentication, quoted parameters, header budgets, challenge-bearing 401s, unavailable snapshots, configuration/input isolation and compiled-bundle compatibility. Public fixtures and fresh ephemeral test keys are never printed or persisted as live credentials.

`REPLAY_SCRIPTS.snapshot` and `.claim` each expose immutable `{ source, sha1 }` values. Both sources share the same guard validation and derive constants from the frozen protocol. The controller must load these exact UTF-8 bytes before enabling a fresh run and put their hashes into the manifest **before computing its configuration digest**. Workers will use only `EVALSHA`; script loss must close the run, never trigger live reload. Bootstrap must separately compare every policy field with the trusted manifest, as specified in the [technical design](../../../docs/implementation/TECHNICAL_DESIGN.md).

Snapshot is read-only and returns authoritative Redis time after checking exact guard keys, hash fields/types, non-expiring policy/clock, run/key/configuration identity, canonical integers and consistent clock highwater. Claim repeats those checks atomically, refuses a candidate from another epoch, validates the spent-key name/representation and uses `SET NX PXAT` to select one winner. Spent records expire at epoch end plus the configured guard; a replay neither refreshes nor refunds them. Responses follow the frozen tagged-array ABI; the future adapter must validate them with the shared `parseSnapshotReply` / `parseClaimReply` helpers.

An unsafe result, malformed reply, script error, timeout or ambiguous mutation must **terminally close the caller's run latch**. These scripts do not implement that latch, supervise leases or authorize forwarding. They never repair missing guards, and snapshot cannot persist closure because it is read-only. Redis Lua serializes execution but does not roll back writes after a runtime error. No uncertain claim may be retried or refunded. Safety assumes trustworthy non-regressing Redis/host time and no silent state rollback; the clock tests cover detected regressions against recorded highwater, not arbitrary unseen clock excursions.

Real Redis component tests require Docker and run separately from the Docker-free `check:g0` suite:

```powershell
npm.cmd run test:replay --prefix src/services/gateway
```

The harness starts a digest-pinned Redis 7.4.8 container with no host ports, external network or persistent data. It tests 20 concurrent claims, exact expiry, a real epoch transition, identity/encoding failures, guard corruption, recorded clock regression, malformed spent state, a deliberately discarded committed reply and missing scripts. The test-only administrative connection seeds/resets isolated fixtures; it is not the production gateway ACL or connection adapter. Minimal script-internal ACL commands for later integration are `TYPE`, `PTTL`, `HLEN`, `HMGET`, `TIME`, `GET`, `PEXPIRETIME`, `HSET` and `SET`, in addition to `EVALSHA` and the separately reviewed client handshake. [Redis scripting](https://redis.io/docs/latest/develop/programmability/eval-intro/) and [absolute expiry inspection](https://redis.io/docs/latest/commands/pexpiretime/) document these server behaviors.

Docker: `docker build -f src/services/gateway/Dockerfile -t tokenforge-g0:local .` from **root**, then run without network/privileges. The image still uses the metadata smoke entry; it is not a serving gateway. The root `check:g0` command runs both consumers and the additional verifier tests.

See `docs/security/DEPENDENCY_REVIEW.md` for the scoped patched transitive dependency and byte-buffer integration constraints. Service-local package lock is authoritative. No root workspace or another owner's private code import.
