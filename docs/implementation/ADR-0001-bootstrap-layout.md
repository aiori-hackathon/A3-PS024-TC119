# ADR 0001 — repository layout and reproducible bootstrap

Status: implemented G0 candidate, 24 October 2026; consumer review pending.

The organizer-created `src/README.md` requests implementation source under `src/`. Map the plan's contracts/services/security to `src/contracts/`, `src/services/`, `src/security/`; retain root tooling/config/infra/docs ownership. Copied plan v1.2 records this path-only refinement; v1.1 security semantics remain.

Node 24.22.1, npm 11.19.1 observed locally. Runtime base: `node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205`. Gateway tools: TypeScript 5.9.3, esbuild 0.28.2, Node types 24.19.2, Ajv 8.20.0. Package locks are service-local; root has no dependencies/workspace/lockfile. CI action commit pins were resolved from the official repositories' v6 refs on this date.

Contracts bundle from the repository root Docker context. The G0 image is explicitly a contract/build smoke image and opens no listener. Real gateway, replay scripts, private origin and Compose lab are subsequent work, not hidden behind a passing G0 smoke command. Existing submission PDFs/video link and `src/README.md` are preserved.

`TF-PS024-1.0.0` is a candidate until both agents accept executable fixtures. Initial inventory caps: demo 10, security 128, benchmark 16384 per run, all before enable. These bound provisioning; they are not a measurement of production memory use or anonymous per-person quotas. Large trials use separate fresh runs as necessary.

Mihir's consuming package/Compose and independent derivation remain his files/tasks. Krish does not create them to make G0 appear closed. The user will supply Mihir's CODEOWNERS login; commented entries intentionally remain pending.
