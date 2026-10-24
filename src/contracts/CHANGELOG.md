# Contract changes

## TF-PS024-1.0.0 — G0 candidate, 24 October 2026

Initial executable candidate for reviewed plan v1.2 (v1.1 security semantics, source mapping under `src/`). Not frozen until Mihir independently validates golden fixtures and consumer builds. Schema/fixture revisions before that acceptance must be recorded here; do not claim G0 passed from the Krish package alone.

Includes domain-separated context/spend/voucher encodings, bounded resource profiles, strict manifest/control/report schemas and typed replay results. Library wrappers must copy typed-array views into exact standalone buffers; the pinned library contains parsers/serializers using `.buffer` without a view offset. Live keys remain fresh; fixtures are public test data only.
