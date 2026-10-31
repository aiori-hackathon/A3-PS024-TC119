# Running and demonstrating TokenForge

Everything here runs on one private host with Docker (Linux containers) and Node 24. No service is published to the host or the internet; the controller reaches roles with `docker exec`.

## Setup (once per checkout)

```
npm ci --ignore-scripts --prefix src/services/gateway
npm ci --ignore-scripts --prefix src/services/lab
node infra/scripts/provision-secrets.ts       # writes git-ignored .runtime/secrets/, refuses to overwrite
node src/services/lab/src/controller/cli.ts preflight
```

On Windows PowerShell use `npm.cmd`. `preflight` prints one JSON line per check and exits non-zero if any fails. Certificates last seven days; delete `.runtime/secrets` deliberately to rotate.

## The demonstration

```
node src/services/lab/src/controller/cli.ts run --suite demo --out artifacts/demo-report.json
node src/services/lab/src/controller/cli.ts verify-report --file artifacts/demo-report.json --require-pass
```

It takes roughly ten minutes (it builds images on first use). Each fresh generation prints `enabled`, then `scenario` lines, then `closed` with `reset_confirmed:true` and the origin's settled counters. Expect these results:

| Moment | What to point at |
|---|---|
| Healthy flow | `healthy-flow PASS`; the closed line shows the origin received 1 and served 1 |
| Shared egress | five clients, ten tokens through one proxy; origin received 10, served 10; the reused token was refused |
| Valid signature, wrong context | `wrong-context PASS`; the origin received 0 although the signatures were genuine |
| Replay | `sequential-replay` (received 1) and `concurrent-replay` (20 simultaneous presentations, one win, verification on both workers) |
| Bearer-token limit | `stolen-unused-token PASS`: a thief using a copied unused token wins first and the holder loses. State plainly that Privacy Pass alone does not bind a token to its holder |
| Fenced fresh-run recovery | `reset-new-generation`: credentials from the old run, one spent and one unused, are refused under the new key; a fresh credential works once. Between the two generations the log shows `closed ... reset_confirmed:true` |
| Dependency fault | `redis-fault`: Redis scripts are flushed under a live run; no valid token is accepted, the origin is untouched, and the controller closes the run on the gateway's own failure |

The final line `{"event":"report","ok":true,"status":"PASS"}` and `verify-report --require-pass` exiting 0 are the pass criteria. A partial or failed run is reported as INCONCLUSIVE or FAIL, never PASS.

## The full security suite and the measurements

```
node src/services/lab/src/controller/cli.ts run --suite security --out artifacts/security-report.json
node src/services/lab/src/controller/cli.ts run --suite performance --out artifacts/benchmark-report.json
node src/services/lab/src/controller/cli.ts verify-report --file artifacts/security-report.json --require-pass
```

The security suite runs all seventeen required scenarios in twelve fresh runs (about twenty-five minutes, of which the epoch-boundary run alone waits about 100 seconds for a real boundary). The performance suite runs the same declared load against the one-worker and the two-worker gateway. Read the performance table in `docs/lab/SCENARIOS_AND_REPORTS.md` before quoting a number: at this load the two profiles are not distinguishable, and the figures describe this laptop only.

## Showing a report in a browser

```
node src/services/lab/src/controller/cli.ts serve-report --file artifacts/security-report.json
```

Then open `http://127.0.0.1:4173/`. The viewer is read-only, loopback-only and shows only a report that passes the same validation as `verify-report`. To show it from another machine, use an SSH port forward to the host's loopback port; never rebind it to another address.

## If something goes wrong

| Symptom | Action |
|---|---|
| `closed ... control-lost` with a `lost_role` while a heavy scenario ran | Supervision correctly closed the run because a heartbeat acknowledgement was late (a busy host). Close other containers or wait, then rerun; do not lengthen any deadline |
| `project-lock-held` | A previous controller did not finish. Run `lab fence`, confirm every role says `fenced:true`, then delete `.runtime/project.lock` yourself. A stale lock is never removed automatically |
| `old-generation-unconfirmed` | Containers from a previous run could not be confirmed stopped (Docker unreachable or unresponsive). Fix Docker, then `lab fence`; do not recreate by hand |
| `lock-retained` at the end | Shutdown was not confirmed. The lock stays on purpose; `lab fence` and inspect before running again |
| Docker daemon down mid-run | The controller will not discard Redis on an unknown state. Restart Docker, run `lab fence`, then start again |
| A scenario FAIL | The `failed_checks` list in the scenario line names the fixed check. Re-run that suite alone (`gateway-core`, `redis-faults`, `upstream`, `retention`, `epoch-boundary`, `admission-limits`) before the full demo |
| Images stale after a code change | `docker compose -f infra/compose.yaml build`; the controller also builds on every run |

Emergency stop at any time: `node src/services/lab/src/controller/cli.ts fence`. It asks every role for a strong FENCE and, failing that, kills and confirms the container.

## Other checks

```
node infra/scripts/check-network.mjs      # reachability, CONNECT misuse, hardening, Redis posture
node infra/scripts/check-roles.mjs        # real issuer/origin/client containers, partial deployment
node infra/scripts/check-controller.mjs   # controller supervision, lease expiry on controller loss, lock handling
```

## What this does not claim

It does not claim Privacy Pass solves token theft, enrollment or Sybil resistance, protection against arbitrary clock rollback (only a regression against the recorded highwater is detected, and the store's wall time is assumed trustworthy and non-regressing), protection from a host or root user, or exactly-once delivery to the origin (a claim can be spent while the origin response is lost). It is a laboratory on one host; Redis and the origin link are plaintext on internal networks.
