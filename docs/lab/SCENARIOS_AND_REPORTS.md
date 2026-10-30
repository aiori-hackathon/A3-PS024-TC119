# Scenarios and reports

**Contract:** `TF-PS024-1.0.0`, unchanged. **Paths:** `src/services/lab/src/client/`, `src/services/lab/src/controller/`, `src/services/lab/src/report/`.

Every scenario below runs against the real deployment (real issuer, CONNECT proxy, gateway with two workers, Redis and private origin). The controller never takes a client's word: it reads the origin's received/mismatch/served counters and the gateway workers' verification counters before and after, and decides PASS from those.

## Status

| ID | Scenario | State | How it is checked |
|---|---|---|---|
| S01 | `healthy-flow` | **passes on the deployment** | challenge, issuance, finalization, redemption; origin received 1, served 1 |
| S02 | `shared-egress` | **passes** | five clients, two tokens each through one proxy; origin received 10, served 10; a reused token refused |
| S03 | `voucher-policy` | **passes** | unknown/missing vouchers 403; a protocol-invalid request is 422 and spares the voucher; one signing per voucher; origin untouched |
| S04 | `malformed-token` | **passes** | 21 size, encoding, type, duplicate-parameter, header-count/size, body and framing abuses refused; origin received 0; gateway still serves afterwards |
| S05 | `signature-and-key` | **passes** | modified nonce/digest/key id/authenticator, all-zero authenticator, random token and a REAL token under another issuer key all 401; origin received 0 |
| S06 | `wrong-context` | **passes** | genuinely signed tokens for the next epoch and for another run id are refused; origin received 0 |
| S07 | `sequential-replay` | **passes** | first use accepted, two more refused as replays; origin received 1 |
| S08 | `concurrent-replay` | **passes** | 20 simultaneous presentations; exactly one win per healthy trial, nineteen replays; verification attempts on both workers (for example 19 and 21); origin received once per win |
| S09 | `epoch-boundary` | **not implemented** | needs a dedicated run whose start is moved back so the 600 s boundary falls inside the run |
| S10 | `admission-limits` | **not implemented** | the 64-tunnel proxy ceiling is below the 128-socket gateway ceiling, so an honest flood needs a harness on the gateway network |
| S11 | `upstream-failure` | **passes** | origin paused with `docker pause`: 502/504 within the deadline, the claim stays spent (the same token is a replay afterwards), no retry; origin received 1, which is the honest "delivered but reported as failed" case |
| S12 | `redis-failure` | **passes, four faults** | script flush, deleted clock, corrupted policy, stopped Redis: no valid unspent token accepted, origin received 0, supervision closes the run on the gateway's own failure, reloading scripts does not revive it |
| S13 | `restart-and-reset` | **passes** | a spent and an unused credential cross a confirmed full reset in controller memory; both are refused under the new key; a fresh credential works once |
| S14 | `network-boundaries` | **passes (client half)** | five direct paths closed, four names unresolvable, thirteen CONNECT misuse cases refused, with a positive control; the proxy-side half is `infra/scripts/check-network.mjs` |
| S15 | `retention-audit` | **not implemented** | |
| S16 | `stolen-unused-token` | **passes** | a thief presenting a copied unused token first wins, the holder is then refused. This is the bearer-token limit, reported as such |
| S17 | `clock-rollback` | **passes** | a recorded highwater ahead of the store's clock closes the run and nothing is accepted. Only the recorded-highwater case is covered; an arbitrary unseen clock excursion is not detected |
| S18 | `performance` | **not implemented** | |

## Suites

`lab run --suite demo` runs the five fresh generations the frozen protocol needs for a complete demo and writes a validated report. On the final code it produced `overall_status: PASS`, accepted by `lab verify-report --require-pass`. `gateway-core`, `redis-faults` and `upstream` are smaller suites. A suite is PASS only if every scenario the contract requires for its kind ran, each PASSED, and each had origin evidence. The security suite stays INCONCLUSIVE until S09, S10 and S15 exist.

The demo suite's five generations: shared egress (demo client profile); a core run (healthy flow, wrong context, replays, theft); the old generation of S13; the new generation of S13; a Redis fault. S08 needs the bounded security client profile (24 gateway sockets), so it cannot share the ordinary demo-profile run.

## Rules the code enforces

- **A client's word is not evidence.** A client PASS while the origin saw an arrival is a FAIL; a scenario with no independent rule is INCONCLUSIVE; a client FAIL stays FAIL.
- **Not tested is not failed.** An unimplemented scenario is INCONCLUSIVE with `missing-evidence`.
- **Fail closed means either a 503 or a dropped connection.** After a replay-store fault the gateway may answer "unavailable" or close the run and the connection; both are accepted, acceptance of a valid token is not.
- **Reports are write-validated and atomic.** Nothing is written unless the shared validator accepts it; a rejected write leaves the previous snapshot. A generation that only quarantined credentials for the next one has no row of its own; the suite continues only because its shutdown was confirmed.
- **Privacy.** Only fixed-schema aggregates are recorded. `verify-report` rejects 64-hex values outside `config_digest`/`token_key_id`/image digests, long opaque strings, address-like text and key markers.

## Quarantined credentials (a recorded test-only exception)

S13 and S16 need a token to move between processes. There is no export command on any role. Instead the controller runs one-shot harness processes inside client containers (`dist/harness.mjs`); a token travels on a private pipe into controller memory, is handed to another harness process on stdin, and is zeroed afterwards. For S13 it also survives one confirmed reset inside an in-memory `Vault` that is cleared when the suite ends. JavaScript strings cannot be deterministically erased, so this is memory hygiene, not a forensic guarantee. Normal clients never reveal a token, and nothing here is serialized into a report or log.

## Not done

S09, S10, S15, S18; the measurement histograms; the read-only viewer. Fault injection that needs a test-only transport seam ("claim committed, reply discarded") is covered by the gateway's own Redis tests, not by the deployed suite.
