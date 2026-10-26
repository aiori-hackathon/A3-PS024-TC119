# Gateway

G0 establishes the contract/library/build path. The first gateway component, `TokenVerifier`, now validates raw binary tokens. **No HTTP listener, Redis claim script or protected forwarding exists yet.**

`TokenVerifier.prepare(manifest)` copies and validates trusted configuration and imports only the issuer public key. `verify(wire, expectedEpoch)` checks exact Type 2 length, full key ID, public signature and configured challenge digest. It owns copies of incoming byte views before awaiting crypto. Rejections use fixed labels without reflecting credentials.

Success returns a `claim-candidate` with spend ID and epoch, not an authorization decision. The HTTP adapter must obtain `expectedEpoch` from a safe authoritative snapshot; the later atomic Redis claim must recheck current time/context before any forwarding. Repeating this component alone does not prevent replay. Do not log returned spend IDs or raw token data.

From repository root (PowerShell uses `npm.cmd`; other shells use `npm`):

```powershell
npm.cmd ci --prefix src/services/gateway --ignore-scripts
npm.cmd run typecheck --prefix src/services/gateway
npm.cmd test --prefix src/services/gateway
npm.cmd run build --prefix src/services/gateway
npm.cmd run test:bundle --prefix src/services/gateway
npm.cmd audit --prefix src/services/gateway
```

Build outputs are `dist/bootstrap.mjs` (public metadata smoke entry, exits) and `dist/token-verifier.mjs` (standalone validation component). Tests include real signed wrong-context tokens, malformed/tampered wire inputs, configuration/input mutation isolation, public-only verification and compiled-bundle compatibility. Public fixtures and fresh ephemeral test keys are never printed or persisted as live credentials.

Docker: `docker build -f src/services/gateway/Dockerfile -t tokenforge-g0:local .` from **root**, then run without network/privileges. The image still uses the metadata smoke entry; it is not a serving gateway. The root `check:g0` command runs both consumers and the additional verifier tests.

See `docs/security/DEPENDENCY_REVIEW.md` for the scoped patched transitive dependency and byte-buffer integration constraints. Service-local package lock is authoritative. No root workspace or another owner's private code import.
