# Gateway — G0 candidate

Current contents prove the contract/library/build path. **No HTTP listener, live gateway, Redis claim script or protected forwarding exists yet.**

From repository root (PowerShell uses `npm.cmd`; other shells use `npm`):

```powershell
npm.cmd ci --prefix src/services/gateway --ignore-scripts
npm.cmd run check:g0
npm.cmd audit --prefix src/services/gateway
```

Package commands: `typecheck`, `test`, `build`. Build smoke output is `dist/bootstrap.mjs`; it prints public configuration metadata and exits. Independent tests use public fixture vectors and fresh ephemeral keys without printing/persisting credentials.

Docker: `docker build -f src/services/gateway/Dockerfile -t tokenforge-g0:local .` from **root**, then run without network/privileges. This is a G0 image; replace its entry point only as K02–K04 implement the serving gateway and tests.

See `docs/security/DEPENDENCY_REVIEW.md` for the scoped patched transitive dependency and byte-buffer integration constraints. Service-local package lock is authoritative. No root workspace or another owner's private code import.
