# TokenForge — preimplementation review record

**Date:** 23 October 2026

**Final joint review:** 24 October 2026 — no further static blockers found

**Reviewed baseline:** [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md), version 1.1, and both agent handoffs

**Reviewers:** primary agent, with an independent Astra design review

**Decision:** proceed to Gate 0 bootstrap in the actual clone; parallel service implementation starts only after that gate passes.

The architecture and folder split are suitable for the scoped hackathon prototype. This review found issues worth correcting before implementation. The corrections below are incorporated into the main plan and relevant handoffs. Runtime compatibility, replay correctness and deployment remain things to prove with executable checks; this is not a claim that the application has already passed them.

## Findings corrected

| Priority | Finding | Correction now in plan |
|---|---|---|
| P0 | Replay TTL safety omitted a necessary clock/state assumption from the earlier research | Explicit trustworthy non-regressing Redis/host wall clock and no silent state rollback. S17 tests recorded-highwater regressions only. No arbitrary-clock-rollback guarantee |
| P1 | Redis scripts did not receive the configuration digest although runtime correspondence was required | Both calls take the expected digest; snapshot echoes it; mismatch closes the run. Exact HASH fields, decimal values, initial guard, typed results and policy/readiness checks specified |
| P1 | A naive synchronous scenario handler could block FENCE/STATUS or controller heartbeats | Bounded concurrent dispatch, correlated responses, independent role I/O, cancellable scenario and priority stop path |
| P1 | First lease installation and repeated ENABLE were ambiguous | Initial ENABLE installs the first deadline before admission; repeat ENABLE cannot renew it; terminal closure cannot be undone by returning to FENCED |
| P1 | A gateway abort cannot undo work already delivered to the private origin | Origin closes/settles or is terminated before reset; fresh origin process/counter; run-generation check; unavailable settled counter is INCONCLUSIVE, not zero |
| P1 | Blanket issuance 400/voucher 401 and challenge-less gateway 401 branches were inconsistent with HTTP/protocol rules | Issuance protocol-invalid type/key/size → 422, framing → 400, local voucher refusal → 403. Every gateway 401 has a current valid challenge; unsafe challenge generation → 503 |
| P2 | Client inventory provisioning could exceed the control frame size | Both sides use ≤128-item batches within 65536 bytes, duplicate checks, declared bounded totals and a final readiness seal |
| P2 | Shared contract imports were not explicitly matched to Docker build context | Repository-root context, explicit owner/shared COPY inputs, minimal runtime stages and clean independent build proof |
| P2 | Host tooling could inherit Node 22 while only containers used Node 24 | Node 24 is required and checked for host controller/build/test tooling too; controller remains outside baseline containers |
| P2 | Initial PREPARE had no clear accepted digest yet | Initial envelope uses null current digest; proposed manifest/digest is validated from payload, then accepted digest is required for later mutations |
| P2 | A 259-byte transport limit would make the specified wrong-size 422 test impossible | Separate 4096-byte body cap from the valid 259-byte protocol payload; bounded wrong-size requests → 422, over-cap requests → 413 |
| P1 | Origin-side rejection could hide a gateway forwarding bug from a success-only counter | Independent received-before-validation, generation-mismatch and served counters; no-forwarding tests assert unchanged **received** count |

The HTTP corrections were checked against [RFC 9578 §6.2](https://www.rfc-editor.org/rfc/rfc9578.html#section-6.2), [RFC 9577](https://www.rfc-editor.org/rfc/rfc9577.html) and [RFC 9110 §11.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.1). The Type 2/public verification API was rechecked in the [pinned library source](https://github.com/cloudflare/privacypass-ts/blob/4edc0e2bf639a60142a3f809d38ce7bd5c6f8c9e/src/pub_verif_token.ts), and the build-context correction follows [Docker's documentation](https://docs.docker.com/build/concepts/context/).

## Important boundaries retained

- A stolen unused bearer token may win the first claim. Replay prevention stops subsequent use; it does not identify the rightful holder.
- Single-spend authorization does not guarantee successful or exactly-once application delivery. An origin failure after claim can consume the token.
- Blindness is a cryptographic property under assumptions; proxy/IP/timing metadata and a small cohort still permit correlation. No invented anonymity score.
- The host/controller/gateway and intact single-primary Redis state are trusted. No production failover, compromised-host defense or public control-plane exposure is claimed.
- Disjoint writers reduce file conflicts; frozen contracts and integration tests establish compatibility. No plan can promise that arbitrary future changes will never conflict or contain defects.

## Gate 0 checks still required before parallel implementation

| Check | Owner | Passing evidence |
|---|---|---|
| Inspect actual clone/instructions/default branch and preserve existing work | Krish, with Mihir | Agreed mapped tree and clean task branches; no replacement repo |
| Working Linux Docker access and Node 24 host tooling | Mihir; Krish reproduces | Preflight succeeds on chosen development environment |
| Pin exact tools/images and assess license/advisory compatibility | Each package owner; Krish integrates | Committed local locks/pins and documented decisions |
| Real Type 2 spike with selected library | Both | Independent vectors plus generated issue/finalize/public-verify round trip; exact wire sizes |
| Executable contracts and independent derivations | Krish; Mihir checks | Matching canonical context/challenge/config/spend fixtures and negative schema tests |
| Independent clean installs/typechecks/bundles | Each owner | No root workspace, copied contracts or dependency leakage; both consumers pass |
| Root-context Docker build safety | Each Dockerfile owner; Mihir Compose | Contracts included; secrets, recordings and known fixture keys excluded from runtime images |
| All remaining enum/limits/control payload details frozen | Krish; Mihir reviews | Same contract commit/version, strict schemas and profile limits; no undocumented overrides |

These are bootstrap acceptance checks, not reasons to defer planning. After they pass, integrate the real single-worker vertical slice early, then two-worker replay/fault tests, then measurements/deployment. The report viewer and visual polish remain lower priority than protocol and lifecycle correctness.

## Updated files to hand to both agents

- [Master plan](./IMPLEMENTATION_PLAN.md)
- [Krish's handoff](./KRISH_AGENT_HANDOFF.md)
- [Mihir's handoff](./MIHIR_AGENT_HANDOFF.md)
- This review record

Use this updated set together; do not give one agent the previous plan and the other the reviewed version.

## Final review decision — 24 October 2026

The primary agent and Astra performed the requested final independent pass. **No further static blockers were found.** The plan and handoffs agree on the replay/time trust boundary, terminal closure, worker leases, concurrent control dispatch, origin teardown and received counters, HTTP contracts, bounded provisioning and path ownership.

The Lua/RESP contract and service-local dependency/shared-contract build arrangement are implementable. Runs may span multiple epochs under the selected clock/state assumptions; the alternative capped monotonic-lifetime design is not required by this baseline. Document integrity, balanced code fences and relative file links were checked again.

**Proceed to G0; freeze plan v1.1 for implementation.** G0 must prove library/vector compatibility, clean consumer builds, image contents and executable contract agreement in the actual clone. Later gates verify real Redis/concurrency/lease/fence/deployment behavior. Those runtime checks are implementation work and remain pending; this final review does not claim they have passed.

G0 checkout note, 24 October 2026: mapped plan v1.2 and contract TF-PS024-1.0.0 are now candidates in this clone. See `docs/implementation/G0_STATUS.md` for actual checks and pending counterpart acceptance; historical review approval is not G0 completion.
