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
| S09 | `epoch-boundary` | **passes** | a dedicated run whose start is moved back 520 s (from the replay store's own clock) so the first 600 s boundary arrives mid-run. A genuinely signed epoch-0 token held across the boundary is refused (`token-expired` or `token-context-mismatch`); a control token redeemed just before it was accepted; a new-epoch token is accepted; origin received exactly 2 and never the stale one. Takes about 100 s of real waiting |
| S10 | `admission-limits` | **passes, with a stated limit** | all five clients at once: ten stalled (incomplete) requests each must be closed by the gateway within its request timeout while a fresh challenge is still served; then a synchronized burst of 120 distinct signed tokens. In real runs 46 to 54 were refused `gateway-busy`; each was presented again and accepted exactly once, and origin arrivals equalled the successes (120), so a busy refusal consumed nothing. **Not reached:** the gateway's 64-sockets-per-worker cap. The CONNECT proxy admits 64 tunnels in total, below the gateway's 128, so only the queue and active-flow limits are exercised from clients |
| S11 | `upstream-failure` | **passes** | origin paused with `docker pause`: 502/504 within the deadline, the claim stays spent (the same token is a replay afterwards), no retry; origin received 1, which is the honest "delivered but reported as failed" case |
| S12 | `redis-failure` | **passes, four faults** | script flush, deleted clock, corrupted policy, stopped Redis: no valid unspent token accepted, origin received 0, supervision closes the run on the gateway's own failure, reloading scripts does not revive it |
| S13 | `restart-and-reset` | **passes** | a spent and an unused credential cross a confirmed full reset in controller memory; both are refused under the new key; a fresh credential works once |
| S14 | `network-boundaries` | **passes (client half)** | five direct paths closed, four names unresolvable, thirteen CONNECT misuse cases refused, with a positive control; the proxy-side half is `infra/scripts/check-network.mjs` |
| S15 | `retention-audit` | **passes** | run after real traffic in the same live generation (see below) |
| S16 | `stolen-unused-token` | **passes** | a thief presenting a copied unused token first wins, the holder is then refused. This is the bearer-token limit, reported as such |
| S17 | `clock-rollback` | **passes** | a recorded highwater ahead of the store's clock closes the run and nothing is accepted. Only the recorded-highwater case is covered; an arbitrary unseen clock excursion is not detected |
| S18 | `performance` | **measured, B0 and B1** | the same declared load against the one-worker and the two-worker gateway, each in a fresh run; see Performance below |

## Suites

`lab run --suite demo` runs the five fresh generations the frozen protocol needs for a complete demo and writes a validated report. On the final code it produced `overall_status: PASS`, accepted by `lab verify-report --require-pass`. `lab run --suite security` runs all seventeen scenarios the contract requires for the security kind across twelve fresh runs and, on a clean local run, produced `overall_status: PASS`, accepted by `lab verify-report --require-pass`. `lab run --suite performance` makes the benchmark report (B0 run, then B1 run). `gateway-core`, `redis-faults`, `retention`, `upstream`, `epoch-boundary` and `admission-limits` are smaller suites for working on one part. A suite is PASS only if every scenario the contract requires for its kind ran, each PASSED, and each had origin evidence; a partial suite is INCONCLUSIVE by construction. A unit test compares each suite's coverage with the frozen list.

The demo suite's five generations: shared egress (demo client profile); a core run (healthy flow, wrong context, replays, theft); the old generation of S13; the new generation of S13; a Redis fault. S08 needs the bounded security client profile (24 gateway sockets), so it cannot share the ordinary demo-profile run.

## Rules the code enforces

- **A client's word is not evidence.** A client PASS while the origin saw an arrival is a FAIL; a scenario with no independent rule is INCONCLUSIVE; a client FAIL stays FAIL.
- **Not tested is not failed.** An unimplemented scenario is INCONCLUSIVE with `missing-evidence`.
- **Fail closed means either a 503 or a dropped connection.** After a replay-store fault the gateway may answer "unavailable" or close the run and the connection; both are accepted, acceptance of a valid token is not.
- **Reports are write-validated and atomic.** Nothing is written unless the shared validator accepts it; a rejected write leaves the previous snapshot. A generation that only quarantined credentials for the next one has no row of its own; the suite continues only because its shutdown was confirmed.
- **Privacy.** Only fixed-schema aggregates are recorded. `verify-report` rejects 64-hex values outside `config_digest`/`token_key_id`/image digests, long opaque strings, address-like text and key markers.

## Quarantined credentials (a recorded test-only exception)

S13 and S16 need a token to move between processes. There is no export command on any role. Instead the controller runs one-shot harness processes inside client containers (`dist/harness.mjs`); a token travels on a private pipe into controller memory, is handed to another harness process on stdin, and is zeroed afterwards. For S13 it also survives one confirmed reset inside an in-memory `Vault` that is cleared when the suite ends. JavaScript strings cannot be deterministically erased, so this is memory hygiene, not a forensic guarantee. Normal clients never reveal a token, and nothing here is serialized into a report or log.

## Retention audit (S15)

The audit looks at the running deployment, not at configuration text, and returns fixed check ids with PASS, FAIL or INCONCLUSIVE: `app-sinks` (no stored Docker logs, nothing readable through `docker logs`, no regular files in any writable tmpfs of an application container), `proxy-sinks` (Docker driver none, `Syslog Off`, no `LogFile`, no files), `redis-diagnostics` (slow log, ACL log, latency history, keyspace events, persistence off AND empty), `mounts` (only a role's own read-only secret files and read-only configuration; no Docker socket, no writable host bind, no anonymous volume), `runtime-files`, `report-allowlist` (the report built from this run passes the privacy scan) and `host-boundary` (no published port, no host network or PID namespace, no privilege, read-only root, no Docker socket). Inability to look is INCONCLUSIVE, never PASS.

It found one real defect while being built: the Redis image declares `VOLUME /data`, so Docker created an anonymous volume that could hold data outside the container lifecycle even with persistence off. `infra/compose.yaml` now covers `/data` with a tmpfs. Image-layer files (apt logs, faillog) are not runtime history, so only tmpfs areas are searched.

**What it cannot see:** host swap, VM snapshots and memory dumps, and the Windows host's own logs. `host-boundary` covers published ports, privileges and the Docker socket only.

## Performance (S18)

Method: each of the five clients mints 80 tokens (paced, so the issuer heartbeat is not starved; timed as `token_acquisition_ms`), then presents them once each with three requests in flight per client (15 in total, which fits the one-worker B0 gateway: one active flow plus sixteen queued). A busy refusal is counted as a failure and is not retried. Only aggregates leave the client: fixed-bucket histograms (bounds in the frozen protocol), counts, failures and elapsed time, delivered through `REPORT` and merged by the controller. Quantiles are the upper bound of their bucket, and null if they fall in the overflow bucket.

One clean local run on this laptop (Windows 11, Docker Desktop, 16 logical CPUs, 7.5 GiB VM, a Supabase stack running alongside):

| | B0 (1 worker) | B1 (2 workers) |
|---|---|---|
| requests accepted / refused | 400 / 0 | 400 / 0 |
| verification attempts by worker | 400 | 186 and 214 |
| `protected_response_ms` p50 / p95 / p99 | 10 / 25 / 50 | 10 / 25 / 25 |
| redemption phase | 0.33 s | 0.29 s |
| `token_acquisition_ms` p50 / p95 | 1000 / 2000 | 1000 / 2000 |

Read it carefully: **at this declared load the two profiles are not distinguishable.** The redemption phase is a burst of about a third of a second, dominated by the client side. B1 splits work across both workers as designed, but this laptop shows no throughput difference worth reporting, and the numbers are a sample, not a benchmark of record. Token acquisition (about 4.8 per second across five clients) is limited by client-side RSA blinding in JavaScript, not by the issuer. Not measured, because the gateway does not export them under this contract: `verification_ms`, `snapshot_rpc_ms`, `claim_rpc_ms`, `queue_wait_ms`, `authorization_ms`, and the issuer's HTTP time. TLS is established per connection and reused within the pool. Controller supervision (one heartbeat per second per role) is always on; there is no run without it, so its overhead is inside every number and was not measured separately.

Minting at full speed from five clients can cost the supervision deadline (a heartbeat acknowledged later than 1.5 s closes the run, correctly), so the scenario paces itself instead of lengthening any deadline. Roughly one performance run in five still lost a heartbeat on this shared, busy host; the `closed` event names the role (`lost_role`) when that happens. A PASS needs a run where it did not occur, and this is a property of running everything on one machine.

## Viewing a report

`lab serve-report --file artifacts/report.json [--host 127.0.0.1] [--port 4173]` serves one report, read-only. It refuses any host that is not loopback before opening a socket, accepts only GET and HEAD on `/`, `/report.json` and `/style.css`, checks the `Host` header against the loopback names on its own port (DNS rebinding), ignores query strings, never maps a path to a file, sends a locked-down Content-Security-Policy and no script, re-validates the file (schema, evidence rules, privacy scan, 1 MiB limit) whenever it changes and shows nothing that fails, and escapes every value. It refreshes every ten seconds, so a report being rewritten atomically by a running suite is shown as it grows.

## Not done

A native Linux run of the security and performance suites outside GitHub's runner, and a fresh-checkout rehearsal on a second machine. Fault injection that needs a test-only transport seam ("claim committed, reply discarded") is covered by the gateway's own Redis tests, not by the deployed suite.
