# TokenForge agent rules

Read `IMPLEMENTATION_PLAN.md`, `IMPLEMENTATION_REVIEW.md` and your handoff before changes. Organizer ownership/access is already arranged; do not change it. Preserve the existing submission assets and `src/README.md`.

## Exclusive writers

- Krish: root integration/configuration/docs handoffs, `.github/`, `config/`, `scripts/`, `src/contracts/`, `src/services/gateway/`, `src/security/`, `docs/implementation/`, `docs/security/`.
- Mihir: `src/services/lab/`, `infra/`, `docs/lab/`, `docs/demo/`, `docs/submission/`.
- Existing submission assets: no edits unless specifically requested. New unassigned paths need an explicit owner before use.

Read/review other paths freely; request owner changes, do not edit them. No root npm workspaces or dependency lockfile. Each application/test package owns its dependencies and lockfile. Use short feature branches, explicit-path staging, real checks, small commits and regular branch pushes. Never overwrite user/teammate changes or rewrite published teammate history.

## Integration and security

G0 must be accepted by both agents before independent service implementation. `src/contracts/` is the shared authority. Never fork constants or import another service's private source. Contract changes require version/change log/fixtures, coordinated consumer changes and tests.

Node 24 is required. Windows PowerShell: use `npm.cmd`; do not weaken execution policy. Docker builds use the repository root context and explicit COPY paths. No credentials/tokens/private keys, runtime secret folders, dumps or unsanitized reports in Git, logs or image layers. No public control/Redis/private-origin exposure. Real crypto, atomic replay, context verification and strong fenced fresh-key recovery are mandatory; report untested/inconclusive evidence honestly.

Mihir requests shared/root changes under `docs/lab/contract-requests/`. Krish requests lab/infra changes under `docs/implementation/lab-requests/`. Handoffs include task/commit, contract version, owned paths, checks/results, limitations and requested counterpart action.
