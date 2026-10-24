# Bootstrap verification status

**Date:** 24 October 2026

**Contract:** `TF-PS024-1.0.0` candidate

The gateway-side contract and cryptographic compatibility bootstrap passes its local checks. Integration acceptance remains pending until the lab package independently validates the same interfaces.

## Verified

| Check | Result |
|---|---|
| Runtime | Node 24.22.1; Linux Docker Engine 29.2.0 and Compose 5.0.2 available |
| Protocol compatibility | Published RFC token vector verifies; fresh RSA-2048 blind issuance, finalization and public verification pass with 259/256/354-byte wire sizes |
| Independent encodings | Python stdlib context/challenge/configuration/spend/voucher derivation matches TypeScript byte for byte |
| Contract tests | 19 tests pass, including strict schema validation, context boundaries, malformed inputs, isolated byte views and replay-reply parsing |
| Build | Clean service-local install, strict typecheck, deterministic schema check and bundled shared-contract build pass |
| Dependencies | Scoped sjcl 1.0.9 override; audit reports zero known vulnerabilities on the check date; see dependency review |
| Container | Digest-pinned image builds; non-root, no-network, read-only smoke and fresh Linux cryptographic roundtrip pass |
| Runtime contents | Production dependencies and bundle only; project fixtures, development tools and source tests excluded |
| CI configuration | Linux workflow covers tests, independent fixture derivation, dependency audit and container checks; remote result is not inferred from local checks |

## Remaining work

- Validate the independent lab consumer's fixture derivation, package lock, build, image and shared interfaces.
- Review and freeze the same contract candidate across both packages before integrating services.
- Implement and test real HTTP issuance/redemption, atomic Redis claims, worker admission, leases, fencing/reset, proxy isolation and origin-arrival evidence.
- Measure latency and throughput only after the full path passes integration/security checks.

The bootstrap image opens no port. It is not a running gateway, replay store, issuer or deployed demonstration. Library tests do not prove runtime replay prevention or fail-closed recovery.

## Reproduce

```powershell
npm.cmd ci --prefix src/services/gateway --ignore-scripts
npm.cmd run check:g0
npm.cmd audit --prefix src/services/gateway
node scripts/check-secrets.mjs
docker build -f src/services/gateway/Dockerfile -t tokenforge-g0:local .
node scripts/check-g0-image.mjs tokenforge-g0:local
```

With Python 3, independently check the fixture using `python scripts/derive-golden-fixture.py --check`. See [technical design](TECHNICAL_DESIGN.md) for the planned architecture and trust boundaries.
