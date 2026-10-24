# Krish's agent — TokenForge implementation handoff

**Read first:** [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md). This handoff summarizes your assignment; it does not replace the contracts or security invariants in that plan.

Aligned to mapped plan **v1.2**, second review, 23 October 2026. Review findings and remaining bootstrap checks: [IMPLEMENTATION_REVIEW.md](./IMPLEMENTATION_REVIEW.md).

Final joint review, **24 October 2026**: no further static blockers. Use v1.1 as the baseline and proceed to G0; runtime/build proofs remain required before parallel service implementation.

Team TokenForge, A3-PS024-TC119, PDEU. Krish Sonpal owns gateway/replay/security/integration; Mihir Goswami's separate agent owns the issuer/client/lab/infrastructure. Dr. Kaushal Shah is faculty guide. The user will provide the existing clone; do not initialize another repository or change organizer access. No deadline is assumed.

## Your exclusive write paths

- Root integration files explicitly assigned K in plan §3: instructions, README, ignores, root scripts-only package manifest, shared compiler settings, GitHub CI/CODEOWNERS.
- `src/contracts/`, `src/services/gateway/`, `src/security/`, `scripts/`.
- `docs/implementation/`, `docs/security/`.
- The initial root implementation plan/handoff documents.

Do not edit `src/services/lab/`, `infra/`, `docs/lab/`, `docs/demo/` or `docs/submission/`. Read/review freely. Request changes under your `docs/implementation/lab-requests/` and let Mihir implement them. Do not create a root workspace/shared dependency lockfile. Gateway and security have separate owned package/lockfiles.

## First session: bootstrap, not a parallel competing implementation

1. Inspect actual repository status, instructions, existing code, remote and default branch. Preserve user work and map the planned tree onto it.
2. Complete Gate 0 with Mihir's review. Pin actual tool/image patches after a Type 2 library spike. Verify the selected exact package versions still satisfy requirements/security review. Do not use homegrown blind signing or silently switch suites.
3. Create executable contracts, strict schemas and public golden fixtures for all plan §§4–9 interfaces: protocol, canonical context/config digest, Redis script ABI/results, lifecycle, reports, named scenarios and resource profiles.
4. Include independently sourced crypto vectors and independently reproduced context/challenge/spend fixtures. Require both consumers to pass. Confirm strict parser wrappers reject incorrect lengths/trailing data.
5. Add ownership rules/CI and ignore `.runtime/`, credentials, dumps and generated artifacts. Mihir creates his own service/infra files; do not bootstrap them as a second writer without an explicit one-time agreement.
6. Merge Gate 0 and send Mihir its exact commit/contract version before parallel G1 branches begin.

## Build order

| Package | Your deliverable | Integration expectation |
|---|---|---|
| K01 | Shared src/contracts/root tooling | Frozen before divergent code starts |
| K02 | Strict gateway TLS/HTTP/parser/public verification/context | Real client credentials, public-only issuer key |
| K03 | Redis snapshot/claim scripts and adapter | Real Redis atomic single spend, immutable guards, current epoch, fail closed |
| K04 | Lifecycle, two workers, bounded admission, fixed origin | Compatible controller state/control; strong FENCE and lease enforcement |
| K05 | Adversarial/security/fault tests | Independent origin-arrival assertions; multiple workers exercised |
| K06 | Timers/aggregate counters/security/privacy docs | Supports honest B0/B1 and retention evidence |
| K07 | Integrated CI/release checks | Fresh-checkout and deployment verification |

Start with one real vertical slice, then complete the required two-worker B1. Do not wait until the final day to connect the real issuer/client. Expose only agreed control/status/report interfaces; no imports of Mihir's private source and no duplicate controller.

## Critical review points

- Verify public signature, full key ID and canonical context **before** attempting claim. Signature validity alone is not authorization.
- One exact store shared across workers; current epoch only, spent expiry at epoch end + 30 s; no Redis eviction/persistence/failover/resume shortcut.
- TTL safety assumes a trustworthy non-regressing Redis/host wall clock and no silent state rollback. Highwater cannot detect every forward-then-backward excursion; S17 tests observed regressions only. An uncertainty closes the run; a fresh key alone does not repair an untrustworthy clock.
- Both Redis script calls carry the expected configuration digest; use exact HASH field/value/result types in plan §6.1 and compare full policy to the manifest at readiness. Freeze integer/string encodings and corruption tests.
- Treat time/guard/script loss and ambiguous mutation as unsafe. A timeout does not undo a committed claim.
- Hold flow permits until actual completion/abort. Prevent late callbacks from forwarding after closure. No origin retry or untrusted upstream selection.
- Every worker enforces its own monotonic lease, checking expiry before renewal/admission/forwarding; delayed IPC cannot grant a fresh duration. Controller/dependency/process failure latches closure. Strong FENCE waits for actual quiescence or process termination before the controller resets state/key.
- Test cross-worker duplicate redemption using the bounded security-client profile, true wrong context, used vouchers, malformed input, origin timeout, Redis uncertainty, supervisor/controller loss, late heartbeat, clock boundaries and reset. Record overload separately; nineteen replay replies requires twenty actually admitted attempts.
- A copied unused bearer token can be spent by a thief first. Demonstrate/mitigate exposure; never claim theft-proof authorization or exactly-once delivery.
- Aggregate telemetry only. Report assertions must prove rejected traffic did not reach origin; no raw token/voucher/digest/IP request history.
- Every gateway 401 carries a valid current PrivateToken challenge; failure to obtain safe challenge state produces 503. Issuance protocol validation uses the RFC 422 behavior in Mihir's service.
- Initial ENABLE installs the first worker lease; repeat ENABLE cannot renew it. Control handlers must remain responsive during a long scenario. Include origin quiescence/counter availability in the reset evidence; missing counters are inconclusive, never assumed zero.
- Origin no-forwarding assertions use `protected_requests_received`, incremented before generation validation; `generation_mismatches` and `resources_served` are separate. Served=0 alone does not prove the gateway never forwarded.

## Required checks and collaboration

Use service-local `npm ci`, typecheck, tests and build. Run contract tests and meaningful real-Redis/security integration; mocks do not prove atomic replay. Root CI changes are yours, even when requested by Mihir. Contract changes need a numbered request/decision, version/change log/fixtures, consumer updates and coordinated merge.

G0 also proves independent clean builds of shared contract imports and root-context Docker build inputs with no unrelated files/fixtures. Host tooling/controller uses pinned Node 24 as well as the containers. Do not freeze G0 based on schemas alone.

Use short branches and explicit owned-path staging; commit/push meaningful working milestones. Do not reset dirty work, force-push teammate history, stage secrets or claim checks you did not run. Other-owner changes must be requested, not slipped into a fix.

At every integration handoff send:

```text
Task ID:
Branch and commit:
Contract version:
Owned files changed:
Checks run and actual results:
Known limitations / blockers:
Requested Mihir action:
```

Your acceptance criteria are plan §§10–16. A polished viewer is optional; real cryptography, replay/context correctness, fail-closed recovery, isolation and supported evidence are mandatory.

Repository mapping: implementation source lives under `src/`; use the paths in this copied handoff. Windows npm commands use `npm.cmd` when PowerShell blocks `npm.ps1`.

G0 checkout note, 24 October 2026: mapped plan v1.2 and contract TF-PS024-1.0.0 are now candidates in this clone. See `docs/implementation/G0_STATUS.md` for actual checks and pending counterpart acceptance; historical review approval is not G0 completion.

Krish's candidate implementation is in this branch. Do not start K02/K03 until G0 counterpart review/acceptance; review Mihir's G0 response and resolve requested contract updates first. Current scope/proofs: [G0 status](./docs/implementation/G0_STATUS.md).
