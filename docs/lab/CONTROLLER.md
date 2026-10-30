# Run controller

**Contract:** `TF-PS024-1.0.0`, unchanged. **Paths:** `src/services/lab/src/controller/`, `infra/scripts/`. Run with `node src/services/lab/src/controller/cli.ts <command>` (or `npm run lab -- <command>` from `src/services/lab/`). The CLI resolves the repository from its own file location, so the working directory does not matter.

## Commands

| Command | Behavior |
|---|---|
| `lab preflight` | Read-only: Docker reachable, Compose file valid, secrets provisioned, Node 24 |
| `lab run --suite NAME --out F` | Fixed multi-generation suites (`demo`, `gateway-core`, `redis-faults`, `upstream`); writes a validated atomic report after every generation |
| `lab run [--profile demo\|security] [--per-client N] [--scenarios a,b --out F]` | One ad-hoc generation running named client scenarios |
| `lab run --partial` | Development mode without the gateway; uses a partial reset barrier that refuses eight-role runs. Never reports a complete suite as PASS |
| `lab fence` | Emergency stop for every role: strong FENCE, else kill-and-confirm by container ID. Never claims a clean stop it could not confirm |
| `lab verify-report --file F [--require-pass]` | Schema, evidence-rule and privacy check |
| `lab serve-report` | Not implemented |

Output is single-line JSON with ids, states and fixed check names only. No voucher, token, key, password or reply body is printed.

## What one generation does

1. Takes the project lock (exclusive; never removed because of what it contains).
2. **Confirms the previous generation is gone** by immutable container ID (strong FENCE where possible, then kill-and-confirm). Only after every role is confirmed gone is the old Redis removed. If anything is unconfirmed it refuses and the lock stays.
3. Recreates all containers and records every identity in an outer cleanup scope **before** using it.
4. Discovers fresh incarnations of the seven non-gateway roles (each must be FENCED and have never carried a run), asks the issuer for a fresh key, then bootstraps the replay store through the shared artifact (`docs/implementation/REDIS_BOOTSTRAP.md`): scripts loaded and hash-checked, `run_start_ms` from the exact Redis's `TIME`, one atomic empty-store initializer, the minimal gateway ACL, and a field-by-field readiness check.
5. **Launches the gateway** inside its idle container with `docker exec -i node /app/dist/serve.mjs`, delivering `{listen_host, tls, redis}` on stdin, then discovers its control socket and incarnation. Nothing secret is in argv, environment, labels or logs.
6. PREPARE (null envelope digest), the whole voucher cohort in sealed frames of at most 128 (plus quarantined harness vouchers kept in controller memory), READY (the gateway must report exactly the profile's worker count), then ENABLE: origin and clients, the issuer, the gateway last.
7. Supervises with sequenced heartbeats (one outstanding per link) and a Docker event monitor keyed to container IDs.
8. Runs the plan's scenarios, then closes through the real `ResetBarrier` (eight participants with real incarnations and container IDs) and discards the old Redis only with the barrier's single-use receipt.
9. Releases the lock only if shutdown of everything it created was confirmed.

If setup fails before a complete snapshot exists (no manifest or no gateway incarnation yet) the identity-bound cleanup scope stops and confirms every recorded container instead; it never invents values for the barrier.

## Safety rules the code and tests enforce

- **Unknown is not gone.** A container's state is running, stopped, absent or unknown. Only an inspection of the exact ID answering "stopped", or the daemon's explicit "no such object: <id>", is exit evidence. Daemon loss, permission errors, timeouts, empty or garbled output and answers about another ID are unknown and block every Redis discard.
- **Setup is cancellable.** The close promise is published synchronously before any hook runs; every await in setup rechecks it. A delayed callback from an old setup step cannot send another mutation, install state, adopt a late-launched gateway or enable anything. Fifteen race tests pin this.
- **Never blocks the event loop.** Every Docker operation is asynchronous with monotonic deadlines rechecked after each await; the lease was not lengthened to compensate.
- **Role barriers.** The issuer latches a run closed even while its first key is being generated, and checks the controller lease synchronously at admission, at queue promotion and before consuming a voucher. The origin's FENCE waits for a pending bind and for the listener and sockets to close.
- **Faults are real.** Redis faults (script flush, deleted clock, corrupted policy, stopped Redis, regressed highwater) and the paused origin are applied to the live deployment through the controller's own access, only from allowlisted scenarios.

## Findings that real runs exposed (all fixed, all with tests)

1. Docker's event stream carries the container ID in `Actor.ID`, not a top-level `id`.
2. The issuer's lease watchdog was a one-shot timer that could fire early and be forgotten, leaving an expired lease unenforced.
3. The current Docker CLI says `error: no such object: <id>`; the first stricter parser treated it as unknown, which would have blocked every discard.
4. The lab image build must also type-check the host controller, which imports the public reset utility.
5. A faulted gateway stops acknowledging heartbeats, so supervision legitimately closes the run mid-scenario; the fault scenarios treat that as evidence instead of fighting it, and take origin counts from the barrier's settled report when the live read is gone.

## Not done

`serve-report`; scenarios S09, S10, S15 and S18; measurement histograms; a Linux host and a fresh-checkout rehearsal; the deployment scripts for a separate host. Windows cannot deliver a graceful SIGINT to the controller; stopping it abruptly is exactly the case the issuer and gateway leases cover.
