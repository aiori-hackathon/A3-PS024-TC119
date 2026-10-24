# Shared contract candidate TF-PS024-1.0.0

The gateway and lab consume these shared definitions rather than copying constants or importing each other's private implementation. This is G0's candidate, pending validation by both consuming packages. Read the technical design and change log.

- `protocol-v1.json`: exact names, limits, profiles, labels, scenarios and histogram bounds.
- `schemas/`: generated strict JSON Schema draft-07. Update the owned generator and regenerate; CI rejects drift.
- `lib/`: dependency-free Node 24 TypeScript encodings, configuration/key validation, strict schema subset and typed Redis reply checks. Import from your source with relative paths; bundle shared code through the owner-local build. The root package declares ESM.
- `fixtures/policy-golden.json`: independent Python stdlib derivation. Fixed run/key/script hashes are test-only, not usable live setup.
- `fixtures/rfc9578-public.json`: public-only independent token vector, source commit/URL/hash included. No source private key/blinding secret is retained.

Run `node scripts/generate-contract-schemas.mjs --check` and `python scripts/derive-golden-fixture.py --check` from root. Tests run through the gateway package's pinned tools. Do not install dependencies or create a lockfile in this directory/root.

Consumer requirements:

1. Initial PREPARE envelope uses `config_digest:null`; payload carries manifest, proposed digest, role and role_config. Helper validates the manifest's actual RSA-PSS parameters/key ID and matching run/digest. Receiver still enforces role-specific mounts/state/incarnation.
2. Provision at most 128 items/frame and 65536 UTF-8 bytes; chunks carry batch ID/index/expected total/final seal. Schema validation is not receiver-state/duplicate validation; implement both, bound totals by manifest/profile, and reject live refill.
3. First ENABLE initializes the lease; repeated ENABLE cannot renew it. Runtime lease/lifecycle/queue/Redis implementations are not provided by these pure helpers.
4. Snapshot reply is exactly `["SNAPSHOT",run_id,key_id,config_digest,now_ms,epoch,start_ms,end_ms]`; errors are one-element tagged arrays. Claim success is `["CLAIMED",expiry_ms]`, with the frozen one-element error tags. Unexpected types/length/identities fail closed.
5. REPORT includes per-worker verification counts (empty for roles without workers) and separate origin received/mismatch/served counters. Client scenario completion alone cannot prove no forwarding; controller must merge independent origin/gateway evidence before final PASS.
6. Report `suite_kind` declares demo/security/benchmark. A complete PASS needs all required scenarios in `protocol-v1.json`, no incomplete case and available origin evidence. Live/partial reports remain INCONCLUSIVE. No arbitrary diagnostics/token/IP fields are allowed.
7. Canonical public-manifest JSON accepts ASCII strings and safe nonnegative integers only, sorted object keys; hashing includes all agreed limits/endpoints. Report latency floats are separate and must not be passed through that restricted manifest canonicalizer.
8. Header framing/strict auth parsing, actual RSA verification, time guard/atomic Lua claim and fail-closed runtime state are service responsibilities. A passed schema is not authorization.

Schema subset is intentionally limited; unknown future keywords/compositions cause an error instead of silent omission. Tests cross-check against independent Ajv. Public fixture credentials must not become live signing/verification keys. Runtime images exclude fixtures/tests.
