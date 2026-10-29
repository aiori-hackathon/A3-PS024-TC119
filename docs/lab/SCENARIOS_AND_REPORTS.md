# Scenarios and reports (M05, first slice)

**Contract:** `TF-PS024-1.0.0`, unchanged. **Paths:** `src/services/lab/src/report/`, `src/services/lab/src/client/scenarios.ts`, `src/services/lab/src/controller/run.ts`.

## What exists

| Piece | Behaviour |
|---|---|
| `lab run --scenarios a,b --out f.json` | After enabling, runs the named scenarios (fixed allowlist from the contract) one per client in order, writes an atomic report snapshot after each, stops the run with reason `completed`, writes the final snapshot including the closing transitions, then verifies the file |
| `lab verify-report --file f.json [--require-pass]` | Parses, applies the frozen schema and the shared evidence rules, then a privacy scan over every string. `--require-pass` exits 1 for anything but PASS |
| S03 `voucher-policy` | Real issuer. Unknown and missing vouchers refused (403); a protocol-invalid request gets 422 and does not spend the voucher; a legitimate voucher signs exactly once and is not restored; a real finalize and public verification confirm the signing was genuine |
| S14 `network-boundaries` (client half) | From inside a client container: five direct paths (origin, Redis, issuer, gateway, public internet) closed, four names unresolvable, thirteen CONNECT misuse cases refused. A positive control (the issuer tunnel) must succeed first, otherwise the result is INCONCLUSIVE |
| Evidence merge | For every scenario the controller reads the ORIGIN's settled counters before and after and, when a gateway exists, per-worker verification attempts. A client PASS is only a PASS if the origin agrees |

## Rules the code enforces

- **A client's word is not evidence.** A client that reports PASS while the origin saw an arrival is a FAIL. Scenarios with no independent origin rule are INCONCLUSIVE, never promoted. A client FAIL stays FAIL.
- **Not tested is not failed.** A frozen scenario the client does not implement is INCONCLUSIVE with `missing-evidence`. A gateway-dependent scenario (`healthy-flow`) cannot PASS in a run without a gateway.
- **PASS needs everything.** Every scenario the suite requires, each PASS with origin counts available, and no inconclusive retention check. One FAIL anywhere makes the suite FAIL. Otherwise it is INCONCLUSIVE. A suite of two scenarios is therefore always INCONCLUSIVE; the report says so rather than looking complete.
- **Reports are write-validated.** Nothing is written unless the shared validator accepts it; a rejected write leaves the previous snapshot intact; the file is replaced atomically with no temp file left behind.
- **Privacy.** Only fixed-schema aggregates are recorded. `verify-report` rejects any 64-hex value outside `config_digest`, `token_key_id` and image digests, any long opaque string, IPv4/IPv6-like text (except the OS and version strings), and key markers. Vouchers used by a scenario are zeroed after use and never reported.

## Evidence

Unit and component tests: `report.test.ts` (PASS rules, atomic write, verification, privacy scan), `scenario-evidence.test.ts` (origin-agreement rules, per-scenario deltas, gateway dependence, run record and honest partial report), `client-control.test.ts` (S03 against the real issuer in process, S14 logic with injectable probes). The real-container result is in `infra/scripts/check-controller.mjs`, section F; 25 of 25 on the final code, including both real scenarios passing with zero origin arrivals, a verified INCONCLUSIVE report and the controller exiting 0.

## Not done

- S01 and S04 to S13, S15 to S18: they need the gateway, Redis bootstrap or the benchmark harness. Their names stay in the contract list; the client refuses them with `ILLEGAL_STATE` and the controller records them as not tested.
- S02 `shared-egress` needs the gateway (the five-client, ten-spend assertion).
- Retention checks (S15), measurements and histograms (M06), and the read-only viewer `serve-report` (M06).
- The S14 independent half beyond the origin counter: proxy and Redis reachability from the proxy side is covered by `infra/scripts/check-network.mjs`, not yet folded into the report.
- The suite kind is fixed to `demo` for now.
