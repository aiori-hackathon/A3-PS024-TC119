# Regional replay component — K02-A

Additive API revision **regional-replay-1**, regional contract `TF-PS024-REGIONAL-1.0.0`.

`src/contracts/lib/regional-replay.ts` supplies the authoritative Lua, command/reply encodings, controller initializer/readiness and a separate gateway ACL. `src/services/gateway/src/regional-replay-store.ts` supplies a bounded, fail-closed connection pool using the existing `ReplayConnection` interface. Neither is connected to HTTP or a real ARC verifier in this slice. The current serving process and baseline scripts/manifests remain unchanged.

This component enforces window-gated single-spend, not proof validity or five-use admission by itself. K02-B must supply a genuine verified ARC tag or verified Type2 token identity. ARC cryptographic presentation-limit checks and issuer admission are separate prerequisites. Never build a trusted claim candidate directly from unverified request fields.

## Store and bootstrap order

1. While every role is fenced, initialize the baseline store and pass its unchanged `verifyStoreReady()` gate. It requires exactly `pp:policy` and `pp:clock`.
2. `initializeRegionalStore(io, manifest, policy)` repeats that baseline freshness check, loads the additive scripts, and atomically installs `tfr:policy` only if there are still exactly two keys, an intact initial clock and a current regional window. It never replaces a policy or resumes a used generation.
3. Regional controller readiness checks exactly three initial keys. Worker readiness checks the pinned script hashes, exact regional fields and a validated regional snapshot; it does not insist the store remain empty after initialization.
4. Install the separate regional account through `regionalGatewayAclArguments`. Its key permissions are read-only baseline/regional policy, read/write shared clock, and read/write regional spent keys. It has no baseline `pp:spent:*` permission, policy-write permission, script loading, reset, delete or administration capability. The controller owns those operations.
5. Prepare the regional pool while fenced, then let the future runtime's all-worker lease barrier control admission. Pool readiness alone is not permission to serve.

`tfr:policy` is a non-expiring hash with exactly seven fields: revision, run ID, baseline configuration digest, regional policy digest, selected profile, window start and window end. Each operation checks exact expected values and canonical integer encodings. The shared baseline hash/clock validation reuses the **unchanged baseline snapshot script source** inside a local Lua function with its original two-key/three-argument view. The baseline source hashes remain identical.

This extension consumes existing shared-library Docker inputs. Regional constants are now at `src/contracts/lib/regional-v1.json`, instead of the K01 candidate's root JSON location, so both existing service Dockerfiles copy them without changes to Mihir-owned files. Schema and fixture generators follow that authoritative path; values and wire encodings are unchanged.

## Script ABI

Snapshot takes keys `pp:policy`, `pp:clock`, `tfr:policy`. Its eight string arguments are run ID, baseline token-key ID, baseline configuration digest, regional policy digest, profile, regional start, regional end, and baseline run start.

Claim adds key `tfr:spent:<regional-policy-digest>:<spend-id>` and two string arguments: 64-hex spend ID and authenticated `not_after_ms`. Non-holder profiles require exactly `0`. Holder mode requires a safe integer expiry strictly after window start and at most window end. The coordinator must obtain it from an actually verified nonce/proof, not from an unchecked JSON field.

Success replies are `["REGIONAL_SNAPSHOT",run_id,policy_digest,now_ms,start_ms,end_ms]` and `["CLAIMED",retention_expiry_ms]`. Ordinary refusals are one-element `WINDOW_CLOSED`, `NONCE_EXPIRED` or `ALREADY_SPENT` arrays. Unsafe replies are one-element `RUN_UNAVAILABLE` or `CLOCK_UNSAFE`. Unexpected tags, extra values, stringified numeric success fields, wrong identities or wrong absolute expiry are unsafe.

Each claim uses Redis TIME inside the same serialized Lua invocation as SET NX. It enforces `[regional_start,regional_end)` and holder nonce expiry there, including after any earlier application precheck. Existing spent records must be strings with value `1` and the exact absolute expiry `regional_end + baseline_guard`. Malformed or missing guards, clock rollback, conflicting identity, unexpected TTLs or corrupted spent records never trigger repair or a new spend. The retention guard is not acceptance grace.

Regional snapshots and ordinary nonce-expiry refusals update the observed clock highwater. When a regional snapshot/claim observes window end, it atomically sets shared `pp:clock.closed=1` before returning `WINDOW_CLOSED`. Every worker subsequently encounters the closed generation. A later clock rollback cannot reopen an observed closed window or revive a nonce after an observed expiry. This does not claim detection of unobserved clock excursions or silent store rollback; the existing trustworthy-clock/intact-store assumptions still apply.

All integrity/argument/type checks precede writes. Redis errors after a mutation can leave partial state. An uncertain transport result is terminal; never retry, refund or reconnect a live run. Bootstrap failure requires fencing/recovery, not another installation attempt.

## Pool and integration boundary

`RegionalReplayStore.prepare(manifest, policy, connections, onFault)` copies validated configuration, checks the accepted baseline script hashes and expected per-worker connection count, installs loss listeners and verifies additive readiness. It never initializes Redis or loads a script.

`claim({kind:"regional-claim-candidate",spend_id,not_after_ms})` owns primitive values before awaiting. This is an internal structural contract, not a cryptographic receipt. `snapshot()` returns authoritative time for current regional policy. Bounded slots produce `busy` instead of creating an offline queue. Connect/command deadlines use the existing manifest limits, including monotonic checks after promise resolution. Loss, timeout, malformed reply or unsafe state latches closure, closes every connection and suppresses late successful results. The pool exposes an abort signal for future coordinator cancellation.

The first expired-window request receives an ordinary refusal; later workers see the terminal shared clock. Nonce expiry/replay alone does not consume a previously unspent token. A successful Redis claim still requires current lease/cancellation/deadline checks before exactly one fixed-origin send. No controller/gateway runtime routing, actual ARC MAC verification, holder signature validation, five-use admission, IP-mode budget or new UI is enabled here.

## Checks

```powershell
node --test src/services/gateway/test/regional-replay.test.ts
npm.cmd run test:regional-replay --prefix src/services/gateway
npm.cmd run check:g0
```

The focused Redis harness creates one disposable pinned server with no host port, external network, persistence or host data mount. It checks genuine Lua initialization, concurrent single-spend, regional expiry inside a still-valid baseline epoch, nonce refusal without spending, guard corruption and ACL separation. A test-only source copy substitutes exactly one TIME expression to exercise observed expiry/rollback; no host clock is changed and no production test-clock option exists. It does not prove ARC cryptography or end-to-end origin behavior.

Mihir can consume the shared initializer after contract review and before enabling a regional run. Preserve the baseline readiness order; do not weaken its two-key gate. K02-B still waits for accepted ARC public-parameter bootstrap, verified tag extraction and client-helper interfaces.
