# Contract changes

## TF-PS024-1.0.0 — G0 candidate, 24 October 2026

Initial executable candidate for the technical design, with implementation source under `src/`. Not frozen until both consuming packages independently validate golden fixtures and builds. Schema/fixture revisions before acceptance must be recorded here; the gateway package alone does not establish integration readiness.

Includes domain-separated context/spend/voucher encodings, bounded resource profiles, strict manifest/control/report schemas and typed replay results. Library wrappers must copy typed-array views into exact standalone buffers; the pinned library contains parsers/serializers using `.buffer` without a view offset. Live keys remain fresh; fixtures are public test data only.
