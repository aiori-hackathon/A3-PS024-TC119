# Contract changes

## Aggregate evidence revision 3 — 13 November 2026

Report schema **3** explicitly records nullable `reset_confirmed`. Overall PASS requires true for every run. Benchmark comparison additionally requires eight distinct complete metrics, expected process/worker evidence, unique snapshot/claim outcomes with zero failures/timeouts/uncertainty, distinct generations and keys, completed warmups and exact alternating profile/repetition order. At least 1,000 measured successes are required per condition/profile across the three repetitions. The protocol, manifest and limits remain unchanged.

Saved schemas 1 and 2 remain immutable and readable through explicit version dispatch; their historical PASS meaning is labelled in the viewer. A phase transition labelled FENCED alone is not proof that the external reset barrier confirmed shutdown. Regression fixtures cover unconfirmed reset, incomplete/duplicated telemetry, contradictory outcomes, duplicated generation identities, repetition relabelling and legacy reading.

## Additive evidence revision `aggregate-evidence-2` — 13 November 2026

Protocol, manifests, profiles, token encodings and Redis ABI remain TF-PS024-1.0.0. Report schema **2** adds explicit source evidence, process resource aggregates, RPC failure/timeout/uncertainty counts and bounded experiment labels. REPORT control replies accept optional `resources` and `rpc_outcomes`; old producers remain readable. Existing metric names and buckets are unchanged. Shared histogram/resource helpers prevent competing consumer definitions.

`report-v1.schema.json` is retained unchanged for saved reports. `validateReport` explicitly dispatches on schema version. A v1 PASS retains its historical evidence meaning; it does not prove the new shared-source rule. V2 shared-egress PASS requires source equality, at least fifteen authenticated observations, ten first-spend successes, replay refusal and matching independent origin totals. Unknown fields and unknown versions remain rejected. Quantiles are recomputed from buckets, including null overflow quantiles. Fixtures/regressions cover legacy reading, v2 negative evidence and cross-worker equality.

## TF-PS024-1.0.0 — accepted 26 October 2026

Initial executable baseline for the technical design, with implementation source under `src/`. Proposed 24 October; accepted after review of lab commit `f130beb` and independent reproduction of both consumers on 26 October. No wire/schema changes were needed for integration. The combined checks pass 19 gateway, 17 lab and 2 bundle tests; both restricted Linux image checks pass. Subsequent observable changes require a versioned change record and coordinated consumers. Acceptance establishes bootstrap compatibility, not runtime authorization/replay correctness.

Includes domain-separated context/spend/voucher encodings, bounded resource profiles, strict manifest/control/report schemas and typed replay results. Library wrappers must copy typed-array views into exact standalone buffers; the pinned library contains parsers/serializers using `.buffer` without a view offset. Live keys remain fresh; fixtures are public test data only.

## Additive API revision `replay-bootstrap-1` — 30 October 2026

New public module `src/contracts/lib/replay.ts` for both consumers: the authoritative snapshot/claim Lua (relocated from the gateway, source bytes and SHA-1 values unchanged), a controller-only atomic empty-store initializer, Redis `TIME` parsing, the minimal gateway ACL, and a field-by-field readiness check. **No wire encoding, error label, schema, profile or fixture changed**, so `TF-PS024-1.0.0` stands. Producer and consumer coverage: `replay-bootstrap.test.ts` and the real-Redis cases in `redis-adapter-redis.test.ts`. See `docs/implementation/REDIS_BOOTSTRAP.md`.

