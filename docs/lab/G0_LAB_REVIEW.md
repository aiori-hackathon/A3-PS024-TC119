# G0 lab consumer review

**Contract consumed:** `TF-PS024-1.0.0` (candidate), from `src/contracts/VERSION`
**Baseline commit:** `746927cef0925557cd2f0766ce3cb72b544f47ca` (`origin/krish/g0-contract-bootstrap`)
**Lab branch:** `mihir/g0-lab-bootstrap`, stacked on the baseline
**Date:** 26 October 2026
**Scope:** `src/services/lab/` only (package, lockfile, Dockerfile, smoke entry, tests). `infra/` was not needed for G0 and is not created.

This records what the lab package independently verified. It does not close G0: that needs the gateway-side counterpart to accept it, and none of the runtime behaviour (HTTP issuer, controller state machine, Redis, networks) exists yet.

## What the lab package contains

| Path | Purpose |
|---|---|
| `package.json`, `package-lock.json`, `.npmrc` | Own dependencies; same exact pins as the gateway; scoped `@cloudflare/blindrsa-ts -> sjcl 1.0.9` override |
| `src/protocol.ts` | Thin lab wrappers over the pinned library: memory-only issuer key, one library `Client` per outstanding issuance, public-key-only verification. All wire inputs go through `libraryBytes()` and exact length checks. No constants of its own |
| `src/bootstrap.ts` | Smoke entry: real issuance and verification, prints public metadata only. Opens no port |
| `scripts/build.mjs` | esbuild bundle; fails if the shared contract is missing or if gateway source, fixtures or tests enter the bundle |
| `scripts/check-image.mjs` | Container check (non-root, no network, read-only, payload contents, fresh Linux roundtrip) |
| `Dockerfile` | Repository-root context, explicit `COPY` paths, same digest-pinned Node 24.22.1 base, production-only runtime stage |
| `test/fixture.test.ts` | Independent fixture derivation (below) |
| `test/crypto.test.ts` | Real Type 2 issuance and verification |
| `test/controller-contract.test.ts` | Controller needs against the control/response/report schemas |
| `test/bundle.test.ts` | Built bundle is self-contained and runs |

## Checks and actual results

Run on the lab branch with a clean `npm ci`. The host has Node 24.18.0, not the pinned 24.22.1, so the suite was also run in the pinned Linux image.

| Check | Result |
|---|---|
| Clean install (`npm ci --ignore-scripts`), own lockfile | 23 packages; `sjcl` resolves to 1.0.9 |
| `npm run typecheck` (strict, shared contract included) | pass |
| `npm test` | 17 of 17 pass (host Node 24.18.0 and `node:24.22.1-bookworm-slim`) |
| `npm run build` then `npm run test:bundle` | 2 of 2 pass (host and container) |
| `npm audit` (full and `--omit=dev`) | 0 vulnerabilities, 26 Oct 2026 |
| Root `scripts/check-secrets.mjs` | pass |
| Root `scripts/generate-contract-schemas.mjs --check`, `derive-golden-fixture.py --check` | pass |
| `docker build -f src/services/lab/Dockerfile` then `scripts/check-image.mjs` | pass: user `node`, no exposed port, `--network none --read-only --cap-drop ALL`, payload is `dist/bootstrap.mjs` plus production `node_modules`, sjcl 1.0.9, no dev tools, source, fixtures or gateway material |
| Lab and gateway bootstrap `profiles_digest` | identical (`ec14fe5f2449368c5f4474fce268ec8fade6c0eebe1433eb70bc7ad99e3a684c`) |
| Ownership check (`--owner mihir --base 746927c`) | pass: 15 paths, all owned by mihir, no forbidden runtime paths |

Not run: remote CI (it does not cover the lab package yet, see request 001), a second platform, anything that needs Redis, proxy or Compose.

## Independent fixture comparison

`test/fixture.test.ts` derives the golden values itself from `node:crypto` and the public data files, without the contracts encoders and without the Python script. The label strings are written into the test from the plan text rather than read from `protocol.domains`, so label drift would be caught. It reproduces, byte for byte:

- redemption context input and digest, RFC 9577 challenge bytes and digest;
- 98-byte authenticator input, spend ID, voucher digest, truncated key ID;
- the full manifest rebuilt from `protocol-v1.json`, its canonical JSON and the configuration digest.

It then confirms that the shared helpers (`contextInput`, `challengeBytes`, `configurationDigest`, `spendId`, `voucherDigest`) give the same results. No disagreement was found.

## Cryptographic proof

All with the pinned `@cloudflare/privacypass-ts` 0.9.0 / `blindrsa-ts` 0.4.5, using only the standard public interfaces:

- the independent RFC public vector verifies with the public key only, and fails after a bit flip;
- fresh RSA-2048 PSS-SHA384 key: request 259 bytes, response 256 bytes, token 354 bytes; request byte 2 is the truncated key ID;
- the token's challenge digest equals the epoch-0 challenge and differs from epoch 1 and from another run ID. Signature validity alone proves none of that, so the gateway must still compare context;
- wrong key and bit flips at several offsets fail verification;
- 258, 260 and 4096 byte requests are refused before signing; short responses and 353 or 355 byte tokens are refused;
- pooled `Buffer` subviews for request, response and token verify correctly after `libraryBytes()` isolation;
- four concurrent issuances (two epochs) use four separate clients, give four distinct requests and tokens, and all verify; a client cannot finalize twice, and another request's response does not produce a valid token.

## Controller compatibility (schemas only)

Every control command, response and a report were built as the lab controller would and checked with both the shared validator and an independent strict Ajv. They show:

- initial `PREPARE_RUN` has `config_digest: null`, carries the manifest, proposed digest, role and role config; established-digest commands (ENABLE, HEARTBEAT and so on) require a non-null digest and incarnation;
- issuer vouchers are 64-hex digests, client vouchers are 43-character base64url; at most 128 per frame; the frame has batch ID, index, expected total and a final-seal flag;
- ENABLE and HEARTBEAT carry no lease length; a heartbeat has a positive sequence;
- FENCE accepts null run, digest and incarnation, so an emergency fence without a run is expressible;
- READY and ENABLED replies carry worker counts, so B0 versus B1 readiness can be checked;
- a PASS report needs every suite-required scenario with origin counts available; partial reports stay non-PASS; unknown fields are refused.

These are schema facts. Receiver-side state (batch duplicates, totals, seal, lease expiry, fencing, async responsiveness) is not implemented and not tested here.

## Findings and limitations

1. **Schema alone does not enforce three rules.** The PREPARE proposed-digest and run ID match the manifest, and canonical pad bits on client vouchers, are rejected only by `validateControlRequest`. A strict JSON Schema validator accepts such frames. The tests pin this as expected. Every receiving role must call the shared helper, and the client and issuer must not rely on schema validation alone.
2. **The library requires an extractable private key.** `Issuer.generateKey` creates it extractable, and `blindSign` exports it as JWK internally and refuses non-extractable keys. "No raw-secret export" therefore cannot come from WebCrypto non-extractability. It has to come from the code (`LabIssuer` keeps the key in a private field and exposes none) and from process, mount and network isolation. This is not a contract change.
3. **Host Node is 24.18.0.** The container runs the pinned 24.22.1. The repo `.node-version` and engines are met by `>=24 <25`; the exact pin was verified only in the Linux image.
4. **The smoke entry's `verified` is a library roundtrip, not gateway authorization.** It does not show replay prevention, context enforcement or any runtime behaviour.
5. **Root `.dockerignore` excludes `**/test` and `**/fixtures`.** That suits the runtime images but means the container tests above ran from a bind mount, not through the Dockerfile.

## Requests to Krish

See `contract-requests/001-ci-lab-package.md`. No contract field, constant or schema change is requested.

## Acceptance state

Lab side: bootstrap complete as described, pending review. G0 stays open until the counterpart accepts this commit and the two packages are reviewed together.
