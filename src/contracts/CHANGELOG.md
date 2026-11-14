# Contract changes

## Holder gateway and regional ACL integration correction — 14 November 2026

K03 adds real P-256/nonce/Type2-context verification and an explicit prepared gateway factory, reusing baseline RSA verification and the regional atomic claim. The final-runtime payload gains one inert regional library bundle. Real TLS/Redis/origin integration verifies token-only theft refusal, subsequent owner success, cross-pool behavior and single-spend racing. It remains separate from the pending deployed issuer/controller/UI flow.

Native restricted EVALSHA revealed that Redis's outer key admission needs RW access for declared script keys. A command-only ACL selector fixes invocation without granting HSET/SET policy-write access; direct and script-based policy-write rejection are tested. Policy fields, Lua bytes/ABIs, baseline protocol and report schemas do not change in this correction.

## Additive regional wire/gateway revision — 14 November 2026

Freezes ARC's inspected 99-byte public parameter bootstrap and adds strict public envelope schemas, canonical raw JSON/MAC validation and RFC Type2 regional challenge framing. Gateway components authenticate verify-only RPC replies and expose instance-owned once-consumed receipts to the regional claim pipeline. Bounded TLS POST support is enabled only by a prepared regional coordinator; baseline GET behavior and original manifests/reports remain unchanged. Public profile/window enforcement and the actual Rust service/controller deployment are distinct integration gates. No claim of full Rust-to-origin deployment follows from fixture-backed transport tests.

## Additive API revision regional-replay-1 — 14 November 2026

Adds a separately namespaced regional policy/spend store, controller initializer/readiness, constrained regional gateway ACL, exact reply/command helpers and bounded gateway pool. Atomic claims use Redis TIME to enforce regional window and authenticated holder nonce expiry. Observed window end latches shared terminal closure; snapshots/refusals record clock highwater. No baseline Lua bytes/hashes, manifests, report schemas or existing runtime path changed. ARC proof/holder verification and admission remain future integration dependencies.

Moves the authoritative regional constants unchanged into `lib/regional-v1.json` so both existing Docker shared-library COPY inputs contain them. Generators/imports follow the new location. The regional contract version and fixtures retain the same meaning. Counterpart acceptance and real ARC interface gates remain pending.

## Regional candidate TF-PS024-REGIONAL-1.0.0 — 14 November 2026

Separate regional policy and encodings define a one-window-per-fresh-run five-use entitlement, ARC private-service requests/replies and canonical verified spend tags, and ephemeral P-256 holder-context/nonce/proof framing. Five generated strict schemas and independent Python framing/MAC vectors accompany focused Node/Ajv and real P-256 interoperability checks. The implementation specification records public adapter routes, current-window-only admission, key rotation, stockpiling prevention, atomic expiry requirements and privacy limits.

Baseline version, manifests, 600-second epochs, token wire, replay scripts and report schemas 1–3 remain unchanged. Existing runtimes do not consume these definitions. Counterpart acceptance, pinned ARC tag/client-state adapter review, runtime verification/atomic authorization and new regional evidence remain pending. This candidate is not a claim that the regional product is implemented.

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

