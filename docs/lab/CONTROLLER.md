# Run controller (M04)

**Contract:** `TF-PS024-1.0.0`, unchanged. **Paths:** `src/services/lab/src/controller/`, `infra/scripts/`. Run with `npm run lab -- <command>` from `src/services/lab/` or `node src/services/lab/src/controller/cli.ts <command>`.

## Commands

| Command | State |
|---|---|
| `lab preflight` | Read-only checks: Docker reachable, Compose file valid, secrets provisioned, Node 24 |
| `lab run --no-gateway --dev-redis [--per-client N]` | Recreates roles for fresh incarnations, builds and enables one run (issuer, origin, clients A to E), supervises until a role dies or the controller is stopped, then closes through the barrier |
| `lab fence` | Emergency stop: strong FENCE to every reachable role with no run knowledge. It never claims a clean stop for a role that did not acknowledge |
| `lab run` (with the gateway) | **Refused.** Needs the gateway entry point on `main` and the Redis bootstrap artifact (request 002) |
| `lab verify-report`, `lab serve-report` | Not implemented; they belong to the report work (M05/M06) |

Output is single-line JSON with ids and states only. No voucher, token, key, password or reply body is printed.

## Design

- **`LabRun`** (`run.ts`) holds no state that outlives the process. Order: discover fresh incarnations (every role must be FENCED and never have carried a run), fresh run ID, issuer creates its own key, Redis scripts and clock, manifest and digest, Redis policy and ACLs, gateway startup input, PREPARE with a null envelope digest, whole voucher cohort provisioned in frames of at most 128 with a final seal, READY (the gateway must report exactly the profile's worker count), then ENABLE: origin and clients, the issuer, and the gateway last.
- **Supervision:** sequenced heartbeats to the issuer from the moment it is enabled and to the gateway from its ENABLE, exactly one outstanding per link. A late, missing, erroring or misnumbered acknowledgement closes the run. A Docker event monitor (container ID, not service name) closes it when any pinned container dies; loss of the event stream counts as loss of every role.
- **Closing** is one path for operator stop, fault and failed setup: reset barrier first, Redis discard only with the barrier's single-use receipt. If shutdown cannot be confirmed the run stays closed, no discard happens and nothing restarts. A closed `LabRun` cannot be started again.
- **Links** (`link.ts`) validate every frame against the frozen schemas, correlate replies by request ID, cap outstanding requests at nine, time out, and fail every pending request when the link is lost. A reply for an unknown request poisons the link.
- **Docker adapters** (`docker.ts`) pin identity to the 64-hex container ID. Termination is kill then `docker inspect` until the container is gone; the success of the kill call is not accepted. Origin counters are recorded only from the settled REPORT after the origin's strong FENCE; if that cannot be bound to the old run they stay `null`, not zero.
- **Project lock** (`lock.ts`) is created exclusively and never removed because of what it contains. A stale file means an operator must fence and confirm, then clear it.
- **Vouchers** (`cohort.ts`) come from the OS CSPRNG, live only in controller memory until each client receives its own inventory, and the issuer gets digests only.
- **Barrier:** a full eight-role run must use Krish's `ResetBarrier`, which is not on `main` yet. `partial-barrier.ts` applies the same rules to a subset of roles and refuses to be constructed for all eight, so it cannot silently replace the real one.

## Evidence

Unit and component tests (`controller.test.ts`, `docker-barrier.test.ts`) cover ordering, heartbeats, setup-failure closure, unconfirmed shutdown, single-use receipts, identity binding, origin counts and the event monitor. `infra/scripts/check-controller.mjs` runs the real CLI against the real containers; result 20 of 20 on the final code. It covers heartbeats keeping an issuer alive past two leases, SIGKILL of the controller followed by the issuer closing itself when its lease lapsed, the stale lock being left in place and refusing a second controller, `lab fence`, and a killed client container closing the whole run, discarding the old Redis container and exiting 0.

The end-to-end check found two real bugs the in-process tests had missed:

1. **Docker's event layout.** The current event stream carries the container ID in `Actor.ID`, not a top-level `id`, so the first version never noticed a dead container. The monitor reads both layouts and has a test for each.
2. **The issuer's lease watchdog could be forgotten.** It was a one-shot timer. Timers can fire a hair before their deadline, and in that case the handler found the lease not yet expired and did nothing, so after a controller was killed the issuer stayed ENABLED. It passed once and failed once in the real run. The watchdog now re-arms for the remainder when it fires early, and STATUS, REPORT and FENCE also judge expiry first. A unit test drives an early-firing scheduler and a scheduler that never fires. The full end-to-end check passed 20 of 20 once after the fix; it has not been repeated enough times to call the timing exhaustively proven.

## Not done

- The gateway and the real replay-store bootstrap (request 002). The development replay store is a labelled stand-in and installs nothing in Redis.
- Wiring Krish's `ResetBarrier` (the adapters it needs exist and match its documented interface, but it cannot be imported until it is on `main`).
- Graceful SIGINT on Windows (Node cannot deliver it to a child there; the checks stop the controller by killing a container or the process).
- Scenario execution, report assembly, `verify-report`, `serve-report`.
- The gateway ENABLE ordering and its heartbeat were tested against a scriptable fake, not the real gateway.
