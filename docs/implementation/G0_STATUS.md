# Bootstrap verification status

**Date:** 26 October 2026

**Contract:** `TF-PS024-1.0.0` accepted

G0 is accepted after reviewing lab commit `f130beb` against gateway baseline `746927c` and reproducing both consuming packages' checks. Neither side changed the shared encodings/schemas during integration. Runtime services remain the next milestone.

## Verified

| Check | Result |
|---|---|
| Runtime | Node 24.22.1; Linux Docker Engine 29.2.0 and Compose 5.0.2 available |
| Protocol compatibility | Published RFC token vector verifies; fresh RSA-2048 blind issuance, finalization and public verification pass with 259/256/354-byte wire sizes |
| Independent encodings | Python stdlib and independent lab-side Node derivations match the committed context/challenge/configuration/spend/voucher fixture byte for byte |
| Tests | 38 pass: 19 gateway, 17 lab, 2 lab-bundle; no skipped tests |
| Build | Both clean service-local installs, strict typechecks and bundles pass; schema generator and independent Python fixture checks pass; both bootstraps report identical contract/profile digests |
| Dependencies | Separate locks and scoped sjcl 1.0.9 override in both consumers; both full audits report zero known vulnerabilities on 26 October |
| Containers | Both digest-pinned images build; non-root, no-network, read-only smoke and fresh Linux cryptographic roundtrips pass |
| Runtime contents | Production dependencies and bundle only; project fixtures, development tools and source tests excluded |
| CI configuration | Combined local runner and Linux workflow now cover both consumers, independent fixture derivation, both audits and both container checks; integration branch remote result must be observed separately |

The lab review's request 001 is implemented in the root checks/CI. Its notes about extractable in-process signing keys, schema-only gaps and signature-versus-context checks remain valid requirements for service implementation; G0 does not provide those runtime controls.

## Remaining work

- Implement and test real HTTP issuance/redemption, atomic Redis claims, worker admission, leases, fencing/reset, proxy isolation and origin-arrival evidence.
- Measure latency and throughput only after the full path passes integration/security checks.

Next component split: gateway validation/context/replay enforcement in `src/services/gateway/`; issuer/client and private lab environment in `src/services/lab/` and `infra/`. Start separate feature branches from the accepted common baseline. Shared-interface changes require versioned review and both consumer checks.

The bootstrap image opens no port. It is not a running gateway, replay store, issuer or deployed demonstration. Library tests do not prove runtime replay prevention or fail-closed recovery.

## Reproduce

```powershell
npm.cmd ci --prefix src/services/gateway --ignore-scripts
npm.cmd ci --prefix src/services/lab --ignore-scripts
npm.cmd run check:g0
npm.cmd audit --prefix src/services/gateway
npm.cmd audit --prefix src/services/lab
node scripts/check-secrets.mjs
docker build -f src/services/gateway/Dockerfile -t tokenforge-g0:local .
node scripts/check-g0-image.mjs tokenforge-g0:local
docker build -f src/services/lab/Dockerfile -t tokenforge-lab-g0:local .
node src/services/lab/scripts/check-image.mjs tokenforge-lab-g0:local
```

With Python 3, independently check the fixture using `python scripts/derive-golden-fixture.py --check`. See [technical design](TECHNICAL_DESIGN.md) for the planned architecture and trust boundaries.
