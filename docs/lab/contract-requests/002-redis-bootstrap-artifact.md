# Request 002: a public Redis bootstrap artifact for the controller

**From:** Mihir's agent. **To:** Krish (owns `src/contracts/` and the gateway source). **Contract:** TF-PS024-1.0.0; additive only.

## Why

The plan makes the controller the only party that loads the replay scripts, writes `pp:policy` and `pp:clock`, and sets Redis ACLs. It must consume Krish's scripts and schema unchanged. Today they exist only inside gateway private source (`replay-scripts.ts`, the ACL setup inside `test-redis-adapter.mjs`), and the rules forbid the lab from importing gateway private source. The controller therefore has a `RedisPort` interface and a development stand-in, and cannot start a real run with the gateway.

## What the controller needs

A dependency-free module under `src/contracts/` (or another path both packages may import) that exports, with tests:

1. **Script sources and their SHA-1s:** the exact snapshot and claim Lua text and the two SHA-1 values that go into the manifest (`snapshot_script_sha1`, `claim_script_sha1`).
2. **Bootstrap plan as data or a pure function:** given the accepted manifest and the Redis `TIME`, the ordered Redis commands that create `pp:policy` (the eight fields, exact value formats) and `pp:clock` (`run_id`, `last_now_ms`, `highest_epoch`, `closed`), with the `run_start_ms` rule (read from Redis `TIME`, never the host clock).
3. **ACL rules for the `gateway` user:** the exact command and key patterns it needs, including the commands the scripts use internally and the pinned client's handshake commands, so the controller can run `ACL SETUSER gateway ...` without guessing.
4. **A readiness check:** how to verify, after bootstrap and before ENABLE, that the stored policy matches the manifest field by field (the plan says readiness compares all immutable policy fields, not only a stored digest).

The controller will call these through `RedisPort.prepare` and `RedisPort.install` and will not re-derive or edit any of it.

## Also useful

- A public accessor on `ResetBarrier` for the origin counts it collects, or confirmation that the controller should capture them in its own `reportOrigin` adapter. The adapter already does this and does not depend on the answer.
- Confirmation that `ResetBarrier` will be importable from `main`. The controller wires it dynamically and refuses to run a full eight-role deployment without it.

## Current workaround

`lab run` refuses to run with the gateway. A partial run (`--no-gateway --dev-redis`) uses a placeholder replay-store port and a partial reset barrier that itself refuses eight-role deployments. Nothing in the controller fakes a result for the real path.
