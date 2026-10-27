# Reset barrier and fresh-generation recovery

Part 11 supplies a public controller safety utility and a dedicated gateway/Redis recovery test. The deployed issuer/client/origin control services and Compose controller are still required from the lab implementation. The utility's synthetic adapter unit tests and the real gateway/Redis recovery scenario are separate evidence; they do not establish an integrated eight-role deployment.

## Controller integration

Import `ResetBarrier` from `src/security/reset-barrier.ts`. Contract `TF-PS024-1.0.0` and its wire schemas are unchanged. The module has no lab/gateway private-source dependency, Docker driver, CLI or fresh-setup callback. It is intended to be imported by the host controller, under the controller's exclusive project lock.

Prepare one immutable old-generation snapshot containing:

- The accepted public manifest, including old run ID, configuration digest and public key.
- All eight expected participants: gateway, issuer, origin and clients A–E.
- Each participant's discovered 32-hex process incarnation and a distinct 64-hex `instance_id` identifying its immutable container or creation-bound process target.
- The exact old Redis container/instance ID as `redis_instance_id`.

Missing/duplicate roles, incarnations or instance IDs are rejected. A Redis ID cannot alias a serving participant. Plain service names, container names and reusable PIDs are insufficient: adapters must retain immutable container IDs, or process identity plus creation identity. If multiple actors share a container, a trusted adapter must pin their individual creation-bound identities and accurately account for group termination. Do not invent distinct process identities merely to satisfy the interface.

The utility copies the manifest/targets and captures adapter functions before asynchronous work. All callbacks receive the original frozen target; they must not resolve a mutable service name to a replacement process. A lock, target creation identity and continuous incarnation monitoring remain controller responsibilities. Separate barrier instances cannot coordinate competing controllers.

## Adapter obligations

`fence(target, request, signal)` sends the supplied frozen FENCE request over the target's private control channel and returns the actual response. Each operation has a ten-second monotonic deadline, including checks after awaiting. A valid acknowledgement must pass the frozen schema **and** match request ID, old run/config and incarnation, with `ok:true`, `result:"FENCED"` and `state:"FENCED"`. A schema-valid response from a replacement process is insufficient.

An error, timeout or insufficient acknowledgement selects `terminate(target, signal)`. That callback must stop the exact old target and confirm its serving descendants have exited. Successful kill dispatch, a timeout, IPC disconnect or a stop request acknowledgement is insufficient. Return exactly:

```ts
{ role, incarnation, instance_id, exited: true, descendants_exited: true }
```

The three identity fields must equal the supplied target. The utility validates the evidence shape and binding; the trusted adapter must actually obtain the operating-system/container evidence. Fabricated adapter results cannot prove termination. Gateway termination includes both serving workers and their listener ownership.

Termination has its own ten-second deadline. Once FENCE times out, its late successful response cannot replace the chosen termination path. Synchronous exceptions are contained per participant so others are still stopped. A clock regression/failure prevents a receipt and requests best-effort termination; the controller must escalate independently. If any exit remains unconfirmed, the barrier is terminally blocked. Redis-discard is never invoked.

`reportOrigin(target, request, signal)` runs only after the origin supplied a valid strong FENCE. Return its actual settled REPORT response, correlated and bound to the same old identity in FENCED state. It must declare origin counts available and provide safe integer `protected_requests_received`, `generation_mismatches` and `resources_served`, with mismatches plus served no greater than received. Only these aggregate counters are retained. Killed origin, report loss, timeout or invalid counters produce `origin_counts_available:false` and `origin_counts:null`, not zero. Safe teardown may proceed, but missing evidence prevents an evidence-dependent PASS. The controller must read settled counters before destroying the origin.

After every participant has quiesced, `fenceAll()` returns one opaque frozen receipt. It is bound to that barrier and Redis identity through private WeakMap state. It cannot be serialized, cloned, forged or transferred to another barrier. Reentrant/repeated calls share one terminal operation.

`discardOldRedis(receipt)` consumes the receipt synchronously before invoking `discardRedis(instanceId, signal)`. The adapter must stop/discard the exact old Redis process/state and confirm its exit, returning exactly `{instance_id, exited:true}`. Clearing keys while leaving the old process live is not this operation. Concurrent, repeated or reentrant consumption cannot invoke discard twice. Failure, timeout, a mismatched exit confirmation or lost successful reply leaves terminal `uncertain` state: no retry or fresh-setup permission is produced. This guarantees at most one callback invocation, not exactly-once external execution.

Only a confirmed `discarded` outcome lets the controller proceed with the remaining old-role teardown and fresh setup under its lock. The controller must still destroy old issuer key/client inventory/public-key caches, generate a fresh signing key/run ID, initialize a fresh Redis process and guards, recreate/discover roles, validate readiness and enable the gateway last. The utility does not perform or prove those steps.

## Gateway/Redis recovery test

From the repository root with Docker running Linux containers:

```powershell
npm.cmd run test:recovery --prefix src/services/gateway
```

The test uses two separate digest-pinned Redis containers and separate generation containers. Each generation runs the production gateway supervisor/workers, real TLS, genuine library blind issuance and an independently counted test origin. It uses the fixed production Redis/origin names through isolated loopback aliases, without host-published ports, external network or a container Docker socket.

The old generation redeems one token, retains one unused token, fences the real gateway, confirms its workers exited, closes the origin and exits its whole generation container. The parent independently inspects that exact container ID for confirmed exit before stopping/discarding the old Redis instance. Only then does it start a genuinely new Redis container and generation with a new run ID, signing key and gateway incarnation. New Redis begins empty; no FLUSHDB or old-process reuse stands in for reset.

Both the spent and unused old credentials must receive `token-key-unknown` with zero new-origin arrivals and zero new spends. A fresh credential must reach the new origin once; reuse must be rejected. Origin received/mismatch/served counters start independently in each generation and are asserted before shutdown.

Two quarantined credentials cross the reset only inside the dedicated test harness's private memory/pipes. Generation stdout is privately captured, Docker logging is disabled, and errors never print that output. No token-export control command, file fixture, environment credential or runtime image secret is introduced. This is the explicit old-credential security-test retention exception; normal clients must clear inventory. JavaScript memory is not claimed to provide deterministic erasure.

The issuer/client/origin here are test fixtures, not Mihir's deployed control services. The test proves actual gateway/fixture-process/container exits and fresh Redis/key/run recovery; it does not fabricate eight deployed-role proofs or validate the full controller/Compose reset. The reset utility's separate tests exercise complete membership, stale identities/correlation, delayed callbacks, unconfirmed descendants, exceptions, unavailable origin evidence and single-use discard receipts. The remaining integration must connect real adapters to the actual lab roles and validate those same obligations end to end.
