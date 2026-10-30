# Redis bootstrap artifact (`replay-bootstrap-1`)

**Module:** `src/contracts/lib/replay.ts`. **Wire contract:** `TF-PS024-1.0.0`, unchanged. This is an additive public API: nothing about encodings, labels, schemas or profiles moved.

The controller is the only party that loads scripts, writes `pp:policy` and `pp:clock`, and administers Redis ACLs. This module is the one place that knows how, so the gateway and the lab consume identical code instead of copies.

## Exports

| Export | Purpose |
|---|---|
| `REPLAY_SCRIPTS` | The exact snapshot and claim Lua (moved here unchanged; `src/services/gateway/src/replay-scripts.ts` re-exports it). SHA-1: snapshot `20b8aa18…1c72`, claim `c4a37fc9…2784` |
| `REPLAY_INITIALIZER` | A third, controller-only script that writes the policy and clock atomically. Never granted to the gateway account |
| `readRunStart(io)` | `run_start_ms` from this Redis instance's `TIME` (canonical decimals, safe integers). Never the host clock |
| `loadReplayScripts(io)` | `SCRIPT LOAD` of the three scripts; each returned hash must equal the expected one |
| `initializeStore(io, manifest)` | One `EVALSHA` that validates every argument, refuses a store with any key at all, refuses a start in the future, then writes the eight policy fields and four clock fields |
| `gatewayAclArgs(user, password)`, `installGatewayAcl(io, user, password)` | The minimal gateway account: keys `pp:policy`, `pp:clock`, `pp:spent:*`; commands `auth type pttl hlen hmget time get pexpiretime hset set evalsha script|exists`; nothing else |
| `verifyStoreReady(io, manifest, gatewayUser?)` | Pre-ENABLE readiness: scripts present; both hashes of the right type, field count and no TTL; every immutable policy field and the exact initial clock; keyspace of exactly two keys; the authoritative snapshot parses; with a username, `ACL DRYRUN` confirms what the account may and may not do |
| `initialStoreState(manifest)`, `policyIdentity(manifest)` | The exact expected values and the three identity arguments the scripts take |

`io` is any object with `call(command, ...args)`; ioredis fits. The password is supplied by the caller and is never stored, logged or included in an error.

## Rules the code enforces

- **Fresh stores only.** The initializer returns `NOT_EMPTY` if `DBSIZE` is not 0, so it cannot overwrite or "repair" a populated or live store. It also checks `start <= TIME`. All checks happen before the first write.
- **No retry into the same run.** Redis does not roll a script back after a runtime error. Any transport failure or unexpected reply throws `replay-bootstrap-uncertain`; the caller must close the run and reset. There is no repair path.
- **No administration for the gateway.** Tests show the gateway account is refused `SCRIPT LOAD`, `EVAL`, the initializer (even with valid arguments), `DEL`, `KEYS`, `CONFIG` and `ACL`, and that readiness fails if the account is given `+script|load` or `+@all`.
- **Stable error vocabulary.** Errors are `replay-bootstrap-<reason>` with fixed reasons (`time-invalid`, `script-mismatch`, `manifest-invalid`, `store-not-empty`, `clock-unsafe`, `invalid-arguments`, `acl-invalid`, `scripts-missing`, `policy-invalid`, `clock-invalid`, `store-not-fresh`, `snapshot-invalid`, `uncertain`).

## Evidence

`src/services/gateway/test/replay-bootstrap.test.ts` (pure, in `npm test`) and the new cases in `redis-adapter-redis.test.ts`, which run against a real Redis 7.4 in an isolated container with the production ioredis adapter: fresh initialization exactness and TTLs, the adapter accepting an artifact-initialized store, TIME parsing, duplicate and populated-store refusal, wrong hashes and future starts writing nothing, thirteen tamper cases failing readiness, ACL over-privilege detection and denial, password absence from errors, and a live run's spent token surviving a second initialization attempt. The pre-existing adapter tests now seed their stores through the artifact, so they exercise it too.

## Limits

- `verifyStoreReady` is a pre-ENABLE check, not a runtime monitor. A store changed later is caught by the gateway's own guard checks and closes the run.
- It assumes a single Redis primary with no replicas or persistence (the Compose configuration); it does not detect restored snapshots.
