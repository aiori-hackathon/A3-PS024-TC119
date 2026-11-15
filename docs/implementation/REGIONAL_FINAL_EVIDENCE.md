# Regional finalization evidence

Observed 15 November 2026 on the intended Windows laptop with Node 24.22.1 and Docker Desktop Linux engine 29.4.0. Application code matches `628c371c70620b9ac7741f2c152aa7864878621d`. ARC binaries embed `05fbb2a4e7649d6bf751ebf6177ff0fcf9dd3ffd`. This Markdown summary contains selected aggregate observations. Frozen baseline JSON report schemas remain separate.

## Complete portal comparison

Actual admitted clients, issuer, CONNECT proxy, production two-worker gateway, restricted Redis, private origin and actual Rust ARC service/helper were used. Each profile had a separately reset fixed 60-second experiment and a 25-use aggregate budget. A made 26 workload attempts, then B–E made five each.

| Profile | State | Accepted | Honest delivered | Denied | Origin received | Origin served | Generation mismatches | Workload source observations | Worker verification totals |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| IP | PASS | 25 | 0 | 21 | 25 | 25 | 0 | 46 | 40, 6 |
| Ordinary Type2 | PASS | 25 | 20 | 21 | 25 | 25 | 0 | 46 | 4, 42 |
| ARC | PASS | 25 | 20 | 21 | 25 | 25 | 0 | 46 | 4, 42 |

All three observed one shared source, both workers participated and gateway claims equalled 25. Queue rejections and transport-failure counters were zero. IP had 21 request rejections. Type2 had 21 replay rejections and 26 request rejections, including its five challenge refusals during preparation. ARC had 21 replay/request rejections. Type2's complete gateway observation total was 51 because preparation contributes five observations, while workload source observations remain 46.

Ordinary Type2 and ARC each used five total issuer HTTP exchanges. Ordinary Type2 batches five independently single-use tokens per entitlement. Observed issuance application bytes were 19,505 for Type2 and 6,635 for ARC. These observations describe one small controlled workload and establish no general performance ranking.

| Profile | Run ID | Policy SHA-256 |
| --- | --- | --- |
| IP | `b3c2b8f60551c59f29364357ef92bfa3` | `d3f4eb8528d61f15db23971f596bce4c5ac2f150940e60d0991fa1722b8feb78` |
| Type2 | `ac4ef6a7f0a67bcb7c28cc542b825a89` | `ab3ecfc24327039f5420ce3ba4c564f10809dafdcd90f867bff086a9d4b2e760` |
| ARC | `4ba975c59b90d36f7e7aa99ad4666025` | `f213315fb51d5ea29cb8e7188a1b8efcdcf352cfd75cfb0877f973bffa9f4185` |

## Holder theft and race

The real portal holder scene passed. Token-only theft caused zero origin arrivals, the subsequent owner request caused one, and twenty duplicate requests caused exactly one additional arrival. Both production workers verified ten race requests each. Each phase required independent origin received/served agreement and zero generation mismatches. Complete signed-request theft and private-key compromise remain explicit limitations.

## ARC private diagnostics

Existing fixed private client actions were selected through the real controller. Its owning gateway control connection obtained authenticated reports. No verifier, cryptography or production gateway was substituted. Before/after origin reports matched run/config/incarnation. Every row below had received/served agreement, zero generation mismatches and matching claim deltas.

| Phase | Accepted | Denied | Origin received delta | Origin served delta | Gateway claim delta |
| --- | --- | --- | --- | --- | --- |
| A malformed proof | 0 | 1 | 0 | 0 | 0 |
| A valid owner | 1 | 0 | 1 | 1 | 1 |
| A subsequent 26 attempts | 4 | 22 | 4 | 4 | 4 |
| B continued access | 1 | 0 | 1 | 1 | 1 |
| C regenerated copied slot | 1 | 0 | 1 | 1 | 1 |
| C owner repeats that slot | 0 | 1 | 0 | 0 | 0 |

The final origin total was seven received and seven served. A first-use copied ARC credential can win. The repeated slot is refused after its verified tag has been claimed.

## Expiry, reset and dependency loss

The actual ARC 60-second window ended and the controller returned to idle. A fresh ARC generation had a different run ID, acquired a new credential and delivered one resource. After its exact Redis container was killed, another access accepted zero and was labelled uncertain. Final independent origin counts remained received 1, served 1, mismatches 0.

Closure inspection confirmed all eight role processes reported authoritative `FENCED` and `run_closed=true`, ARC's container was stopped and Redis was absent. The supported reset barrier permits strong fenced acknowledgments. Baseline role containers can remain alive in their fenced state. Optional ARC is also covered by the emergency fence command, whose actual invocation confirmed its termination.

## Checks and scope

| Command or gate | Result |
| --- | --- |
| `cargo test --offline --locked --manifest-path src/services/arc/Cargo.toml` | 14 native tests passed |
| ARC Docker verification stages | Wrapper/runtime, corrected P256 fork and pinned upstream protocol/vector tests passed, release binaries built |
| Lab build and exact bundle test | 4 tests passed, intended eight bundles |
| Regional controller regression tests | 7 passed |
| `npm.cmd run check:g0` | PASS, 2 local skips for POSIX socket permissions and opt-in native ARC |
| `npm.cmd run test:regional-integration --prefix src/services/gateway` | 4 passed using actual production workers and counted origin |
| `npm.cmd run test:regional-replay --prefix src/services/gateway` | 7 actual Redis tests passed |
| `node scripts/check-regional-consumers.mjs` | 2 native Linux consumer tests passed, 0 skipped |
| `node infra/scripts/check-network.mjs` | 177/177 passed, pre-existing exited optional ARC removed, final project inventory empty |
| Portal tests | 9 passed, fixed commands and Host/Origin/session/CSRF/response bounds |
| Gateway and lab production-image checks | PASS, non-root/read-only/no-network crypto smoke and exact payload checks |
| Final lab typecheck and emergency fence | PASS |
| Gateway and lab npm audits | 0 vulnerabilities |
| Secret signature scan | PASS, selected text signatures checked, no credential values emitted |

The native ARC consumer uses a labelled substitute gateway. The complete portal comparison and private diagnostics above supply the separate production ARC gateway/controller evidence. Holder key/request/nonce substitution, nonce expiry, context/profile refusal, atomic race and observed-expiry/rollback refusal are covered by existing focused real-crypto and Redis tests. Startup cancellation, late resources and retained terminal uncertainty are covered by controller regressions. The full historical local attack/performance campaign was reused. CI additionally runs the deployed baseline demo/security/performance-smoke suites.

Direct-origin, Redis, ARC bridge membership and fixed CONNECT allowlist results come from the real network checker, with its documented positive controls and inactive ARC boundary listener. Live ARC reachability and authenticated operation are demonstrated by the complete deployment. Configuration inspection and actual network reachability remain separately scoped.

## Retained incomplete trials and environment issues

- Historical deployed ARC supervision refusal, older G0 bundle failure and 176/177 network cleanup failure remain in the prior checkpoint.
- An initial private diagnostic attempted gateway REPORT from an additional connection. The owner-only control boundary closed that connection, leaving that diagnostic INCONCLUSIVE. The comparison and holder results had already completed. Repeating only the remaining diagnostics through the owning controller resolved the missing evidence.
- An initial closure audit incorrectly required every container to exit. The follow-up verified the supported authoritative strong-fence contract, final origin counts, stopped ARC and absent Redis. No product assertion was weakened.
- Docker dependency downloads stalled despite HTTP 200 headers. Docker was restarted and its public Cargo cache was warmed from locally cached public registry/Git dependencies. Locked downloads, checksums and all image verification stages still ran. No secret/config credential file entered the seed context. A healthy clean-checkout build requires access to the pinned registries and repositories.
- The browser recorder's available FFmpeg lacked its PNG decoder. The backup uses actual JPEG screen frames encoded as VP8 at one frame per second, labelled recorded evidence. Failed recording attempts are excluded from deliverables.

## Reproduction and packaging

Follow [the regional runbook](../lab/REGIONAL_RUNBOOK.md) for clean-checkout setup, preflight, launch, comparison, holder scene, reset, safe uncertainty recovery and cleanup. Run the commands above for component/native/network reproduction. Private diagnostic action names are `attack`, `access`, `abuse`, `acquire` and `copy`, using the existing container-local regional helper and controller-owned reporting. Public portal commands remain fixed.

The new regional deck and recorded fallback are in `docs/submission/regional/`. [The narration](../demo/REGIONAL_NARRATION.md) supplies the seven-minute evaluator sequence. Original submission PDFs and video links are preserved. Voice/video participation, venue attendance and physical second-device rehearsal remain human tasks.
