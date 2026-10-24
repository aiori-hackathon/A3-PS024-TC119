# Mihir's agent — TokenForge implementation handoff

**Read first:** [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md). This handoff summarizes your assignment; the main plan supplies the protocol, lifecycle and acceptance contracts.

Aligned to mapped plan **v1.2**, second review, 23 October 2026. Review findings and remaining bootstrap checks: [IMPLEMENTATION_REVIEW.md](./IMPLEMENTATION_REVIEW.md).

Final joint review, **24 October 2026**: no further static blockers. Use v1.1 as the baseline and proceed to G0; runtime/build proofs remain required before parallel service implementation.

Team TokenForge, A3-PS024-TC119, PDEU. Mihir Goswami owns issuer/client/controller/lab/infrastructure/demo; Krish Sonpal's separate agent owns gateway/replay/contracts/security/integration. Dr. Kaushal Shah is faculty guide. The user will supply the existing repository clone. Do not initialize a replacement, change organizer access or invent a deadline.

## Your exclusive write paths

- `src/services/lab/` including its own `package.json`, `package-lock.json`, Dockerfile, role entry points, tests and scripts.
- `infra/` including the one authoritative Compose file, proxy/Redis configuration, secret provisioning and private deployment scripts.
- `docs/lab/`, `docs/demo/`, `docs/submission/`.

Do not edit `src/contracts/`, `src/services/gateway/`, `src/security/`, root configuration/CI, or Krish's documentation folders. Send contract/root requests in `docs/lab/contract-requests/`; Krish updates those files. You own Compose, but Krish owns the gateway Dockerfile. No root workspace/shared lockfile and no import of gateway private source.

## First session: agree before building

1. Inspect the actual clone/instructions/status and wait for the reviewed Gate 0 contract/bootstrap merge before independent implementation branches.
2. Review protocol/library API use, endpoint naming, control messages, schemas, Lua ABI, profile limits, report schema and network topology with Krish. Independently reproduce the context/challenge/config digest fixture once.
3. Create only your assigned bootstrap lab/infra files. Pin your own dependencies/lockfile and actual image/tool patches; check licenses/advisories and real Type 2 behavior.
4. Record the same contract version/commit in your progress note under `docs/lab/`. If a required interface is missing, request it; do not invent a competing field or bypass.

## Build order

| Package | Your deliverable | Acceptance |
|---|---|---|
| M01 | Issuer with pinned library, fresh memory-only key, public directory, one-use vouchers | Real blind issuance; no raw-secret export, no double signing authorization/live refill |
| M02 | Node client, CONNECT/TLS, challenge/issuance/finalization/inventory | Strict trust/endpoint rules; one library Client per outstanding issuance |
| M03 | Compose, proxy, Redis environment, private origin and counters | Five exclusive networks; direct private-origin/Redis access denied |
| M04 | Foreground controller/CLI, provisioning, continuous supervision and fence/reset | Exact lifecycle; no authorized orphan run or unsafe state reset |
| M05 | Named scenarios + report generation | Genuine protocol operations and independent origin-arrival deltas |
| M06 | Benchmark harness, read-only report UI and private deployment | Comparable real B0/B1 reports; loopback-only sanitized viewer |
| M07 | Setup/demo/submission documents | Fresh-checkout reproducibility and claims matching measured implementation |

One lab package may share tooling, but issuer, clients and private origin run as separate processes/containers with role-specific secret/network access. Keep the main client Node-based; the browser is a read-only evidence viewer, not a custom Privacy Pass browser extension.

## Highest-risk responsibility: controller and recovery

- Implement plan §5 exactly: discovery/incarnation → issuer key → policy/scripts/manifest → prepare → whole voucher cohort → ready → dependency enable/heartbeats → gateway enable last.
- Control is private per-role UDS through container-local helpers; credentials pass via private stdin, never shell arguments/logs. No public control API or container Docker socket.
- The foreground controller holds one project lock, continuously watches exits/incarnations/helper health, and heartbeats issuer/gateway. Do not use detached setup that exits while authorization stays enabled.
- All roles start fenced; `restart: no`. READY is not ENABLED. Unknown/ambiguous mutations close the run, never automatically reprovision or resume.
- Readiness uses the manifest's worker count: one for B0/G2, two for B1. Heartbeats are sequenced with one outstanding per link; workers enforce their own original monotonic expiry, and no delayed renewal may revive an expired run. Coordinate these fields with Krish.
- Initial ENABLE installs the first lease and requires worker acknowledgement; repeated ENABLE is not renewal. Handle scenario commands asynchronously so STATUS/FENCE/heartbeats remain responsive. Never hold the lifecycle lock while awaiting a scenario.
- Both issuer and client voucher provisioning use bounded batches of at most 128 items, strict total/message limits, duplicate checks and an explicit final seal required for readiness. No live refill or ambiguous retry.
- On stop/fault, request strong FENCE; if acknowledgement fails, kill the old process/container tree and confirm exit. **Only afterward** discard Redis state and old signing key. Failure to confirm exit means remain closed.
- Private origin must also close listeners/sockets and settle or be terminated before the next run; use a fresh origin process/counter. Obtain settled counts before teardown, or mark evidence unavailable/inconclusive. The internal run header prevents old-generation attribution, not authorization.
- Keep origin `protected_requests_received` (increment before generation validation), `generation_mismatches` and `resources_served` separate. Negative tests assert received stayed unchanged; wrong-generation component tests must increment received/mismatch while served remains zero.
- A replacement controller never trusts stale lock files or container names as proof of the old run's death. No Redis flush while old workers are live.

Replay TTL safety assumes trustworthy non-regressing Redis/host wall time and no silent state rollback. Highwater cannot prove arbitrary rollback safety. Do not change host time/restore snapshots during service; detected uncertainty closes the run and requires trustworthy-clock recovery.

Krish supplies scripts/schema/ACL requirements; you provision and call them unchanged. Request any missing permissions/fields explicitly. Redis diagnostics/logging/network configuration is your implementation responsibility, with Krish's audit assertions.

Both script calls include the expected config digest and have exact tagged-array returns/HASH types. Readiness compares all immutable policy fields to the manifest, not merely a stored digest. Host controller/tooling also uses Node 24. Compose builds use repository-root context for shared contracts, explicit COPY paths and safe runtime stages; never mount the Docker socket into baseline containers.

## Scenarios, UI and measurements

Implement the exact `lab preflight`, supervised `lab run`, `verify-report`, `serve-report`, and emergency `fence` interfaces in plan §9. Named scenarios only; keep fixtures/tokens in memory. Emit fixed-schema aggregates, no token/voucher hashes, private keys, IPs or per-request timing history. The viewer has no execution/upload/arbitrary-file endpoint and renders actual PASS/FAIL/INCONCLUSIVE results.

Issuer HTTP: protocol-invalid type/key/size is 422 per RFC 9578; malformed HTTP framing is 400; local voucher refusal is 403. Directory public keys use padded base64url. Test these separately from the gateway's PrivateToken authentication; every gateway 401 requires its challenge header.

Required demonstrations include five clients/two tokens each behind one CONNECT proxy, genuine wrong-context rejection, replay across two workers, origin-arrival evidence, failure/fresh-key recovery and the honest stolen-unused-token limit. Coordinate security hooks with Krish instead of duplicating his tests or editing his files.

Benchmark B0 and B1 with identical security semantics and declared configurations. Separate issuance, crypto verification, claim, queue and full-response latency; preissue unique tokens for verification trials. Provision all vouchers before enable. Do not cross/extend the 600-second epoch or reset a live store to keep a trial running. Show actual counts, errors and conditions; never invent a performance number for the UI/slides.

Deployment is one private Linux host, no public authorization/admin/Redis/private-origin ports; loopback report viewer through SSH/local presentation. A public demo is a separate reviewed change if later required. Keep runtime credentials ignored and never embed them in images/environment/labels.

## Required checks and handoff

Run your package's clean install, typecheck, tests/build, shared contract fixtures, real crypto integration and Docker/network/controller scenarios. Follow the full integration gates in plan §10; no simulated crypto success in final evidence. Krish independently reproduces your runbook before release.

Use short feature branches, explicit owned-path staging and regular verified commits/pushes. Do not reset user work, modify Krish's files to unblock yourself, force-push teammate history or commit credentials/generated captures.

At every integration handoff send:

```text
Task ID:
Branch and commit:
Contract version:
Owned files changed:
Checks run and actual results:
Known limitations / blockers:
Requested Krish action:
```

Your final package is a working lab with reproducible evidence and an honest demonstration. The UI must remain smaller than the protocol, isolation and recovery work it explains.

Repository mapping: implementation source lives under `src/`; use the paths in this copied handoff. Windows npm commands use `npm.cmd` when PowerShell blocks `npm.ps1`.

G0 checkout note, 24 October 2026: mapped plan v1.2 and contract TF-PS024-1.0.0 are now candidates in this clone. See `docs/implementation/G0_STATUS.md` for actual checks and pending counterpart acceptance; historical review approval is not G0 completion.

Your next concrete task is [G0-001 consuming bootstrap](./docs/implementation/lab-requests/G0-001-mihir-consumer.md). Use this repo's candidate branch/commit and create only M-owned files. Your package needs its own scoped sjcl 1.0.9 override; inspect [dependency review](./docs/security/DEPENDENCY_REVIEW.md). Do not create two full implementations before agreeing on these executable schemas.
