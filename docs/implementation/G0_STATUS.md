# Gate 0 status — 24 October 2026

**Branch:** `krish/g0-contract-bootstrap`

**Plan:** mapped v1.2, preserving reviewed v1.1 security semantics

**Contract:** `TF-PS024-1.0.0` candidate

**Overall:** Krish's bootstrap is ready for counterpart review; **G0 is not yet closed**.

## Completed and actually checked

| Item | Evidence/result |
|---|---|
| Existing clone inspected | Organizer remote `aiori-hackathon/A3-PS024-TC119`, default `main`; original submission files and `src/README.md` preserved |
| Local identity | Repository-local `krishsonpal <krishsonpal21@gmail.com>` per user; global configuration not changed |
| Environment | Node 24.22.1, npm 11.19.1, Linux Docker Engine 29.2.0, Compose 5.0.2; PowerShell uses `npm.cmd` |
| Exclusive paths | Code mapped under `src/`, AGENTS rules and explicit-path ownership checker; no M-owned package/infra file created |
| Executable contracts | Protocol profiles, strict manifest/control/reply/report/scenario JSON schemas, canonical encodings and typed Redis result adapters |
| Independent fixtures | Public-only RFC vector; Python stdlib derives context/challenge/config/spend/voucher bytes independently of TS; exact match |
| Crypto compatibility | Independent token verification and fresh RSA-2048 blind issue/finalize/public verification on Node 24; exact 259/256/354-byte wire sizes |
| Tests | 19 meaningful contract/crypto tests pass; strict typecheck; schema generator drift check; esbuild bundles shared contracts; metadata smoke exits successfully |
| Clean install | Service-local `npm ci --ignore-scripts` succeeds; no root workspace/dependency lockfile |
| Dependency review | Narrow sjcl 1.0.9 override; npm audit reports 0 known vulnerabilities after fresh install; Astra reviewed the scoped decision |
| Linux container | Digest-pinned build succeeds; non-root/no-network/read-only/cap-drop/pid+memory-limited run succeeds; fresh Linux crypto roundtrip verified |
| Runtime payload | Only dist/production dependencies in `/app`; no project fixture/test/source payload or TS/esbuild/Ajv dev tools; patched installed dependency confirmed |
| CI | Linux G0 workflow added with pinned action commits, read-only permissions and no persisted checkout credentials; remote CI result is not claimed until run |
| Repository checks | Explicit-path ownership guard and selected accidental-private-credential signatures checked; these do not replace a full security review |

The G0 Dockerfile/entry point is a smoke artifact and opens no port. No real HTTP gateway/issuer, Lua replay scripts, live Redis policy, Compose lab, latency benchmark or public deployment exists yet. Those are G1 onward, not silently inferred from passing library tests.

## Pending acceptance

- **Mihir's agent:** independent consuming package/lockfile/build/image, its own patched dependency override/audit/vector tests, independent fixture comparison, controller/schema review and recorded branch/commit. Exact request: [G0-001](lab-requests/G0-001-mihir-consumer.md).
- **User:** fill Mihir's real login into the five commented entries of `.github/CODEOWNERS`, remove the comment markers, and commit through Krish/the user. No login guessed and no organizer permission/ownership change made.
- **Both:** review the same candidate commit, resolve any contract requests, run both clean consumers and accept/merge G0 through the agreed workflow. Only then start independent G1 service work.
- **CI:** verify the actual remote workflow result once the branch is pushed. Local passing checks do not establish a GitHub Actions result.

## Reproduce Krish's checks

From the repository root:

```powershell
npm.cmd ci --prefix src/services/gateway --ignore-scripts
npm.cmd run check:g0
npm.cmd audit --prefix src/services/gateway
node scripts/check-ownership.mjs --owner krish
node scripts/check-secrets.mjs
docker build -f src/services/gateway/Dockerfile -t tokenforge-g0:local .
node scripts/check-g0-image.mjs tokenforge-g0:local
```

Independent fixture check with Python 3: `python scripts/derive-golden-fixture.py --check`. User machines may use another interpreter location; the repository does not hardcode the agent's bundled Python path.

Security evidence is deliberately limited to what ran. In particular these checks do not prove atomic replay, runtime lease expiry, fence quiescence or network reachability; integration/fault tests must prove those in their scheduled gates.
