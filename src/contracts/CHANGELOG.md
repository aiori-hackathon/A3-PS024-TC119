# Contract changes

## TF-PS024-1.0.0 — accepted 26 October 2026

Initial executable baseline for the technical design, with implementation source under `src/`. Proposed 24 October; accepted after review of lab commit `f130beb` and independent reproduction of both consumers on 26 October. No wire/schema changes were needed for integration. The combined checks pass 19 gateway, 17 lab and 2 bundle tests; both restricted Linux image checks pass. Subsequent observable changes require a versioned change record and coordinated consumers. Acceptance establishes bootstrap compatibility, not runtime authorization/replay correctness.

Includes domain-separated context/spend/voucher encodings, bounded resource profiles, strict manifest/control/report schemas and typed replay results. Library wrappers must copy typed-array views into exact standalone buffers; the pinned library contains parsers/serializers using `.buffer` without a view offset. Live keys remain fresh; fixtures are public test data only.
