# Interactive controls and evidence presentation

Validated on the demonstration laptop on 15 November 2026, building on the configurable-policy implementation at `7add37e`. This supplements the historical regional acceptance and manual-session validation; it does not replace their scoped records.

## Real configurable limits

The real controller, clients, issuer, two production gateway workers, private Redis/origin and Rust ARC service/helper exercised the following operator-selected limits:

| Profile | Configured limit | A attempts | A accepted | A refused | Subsequent B access |
| --- | --- | --- | --- | --- | --- |
| IP | 15 shared | 16 | 15 | 1 | Refused, zero extra origin arrivals |
| Ordinary Type2 | 3 per admitted client | 16 | 3 | 13 | Accepted, one extra origin arrival |
| ARC | 3 per admitted client | 16 | 3 | 13 | Accepted, one extra origin arrival |

An additional IP run with limit 50 sent 51 requests: 50 accepted, one refused and 50 origin arrivals. Controller batching respected the existing private reply-frame bound. Repeated IP acquisition returned not-required; repeated token acquisition returned already-acquired without a refill. All recorded action evidence above was verified, and the controller ended idle.

Focused real Type2 client tests also exercised quotas 1, 3 and 10, exact issuance counts, exhaustion and another admitted client's continued access. Real Redis tests passed all nine checks, including selected shared-IP quotas 1, 3 and 50, concurrent claims, quota-substitution refusal, both window durations, replay, expiry, state corruption and ACL boundaries. ARC image verification passed its real proof checks for selected limits 1, 2, 3, 7 and 10 before building the service/helper binaries. Earlier five-only adapter guards were updated explicitly; cryptographic point validation remains enforced.

## Editable request count

The request-count input previously inherited the access button's disabled state, preventing editing before a run or before acquisition. It is now editable whenever the portal is connected and no command is pending. Sending remains gated on an active window and any required client acquisition.

A real IP run selected limit three and sent a batch of two, then another batch of two. The first accepted two; the second accepted one and refused one. B's subsequent access was refused with zero additional origin arrivals. The frontend module's tests also verify that its entered count is sent unchanged and that stale resource content is cleared on a refused request.

## Comparison reporting boundary

The earlier IP row retained its INCONCLUSIVE result: 25 accepted/served/claimed, both workers observed, but only 45 summed workload source observations against 46 in the final gateway report. Its aggregate shared-source result was therefore not established for every action snapshot.

The controller now performs bounded read-only report settlement for expected completed observations and claims before computing each action delta. It does not resend requests, invent missing counts, reduce the 46-observation threshold or relabel a saved incomplete result. Missing evidence still produces INCONCLUSIVE, with explanatory notes. Focused tests cover a delayed 45-to-46 observation and a bounded deadline that retains the missing observation.

A fresh complete live comparison passed:

| Profile | State | Accepted | Honest delivered | Denied | Origin received/served | Workload source observations | Worker verification totals |
| --- | --- | --- | --- | --- | --- | --- | --- |
| IP | PASS | 25 | 0 | 21 | 25 / 25 | 46 | 33, 13 |
| Ordinary Type2 | PASS | 25 | 20 | 21 | 25 / 25 | 46 | 6, 40 |
| ARC | PASS | 25 | 20 | 21 | 25 / 25 | 46 | 32, 14 |

Every row established one shared source, zero generation mismatches and 25 gateway claims. Recorded issuance application bytes remained 19,505 versus 6,635 for Type2/ARC, with five issuer exchanges each. Latency values are workload observations and establish no universal ARC performance advantage.

## Recorded reference and live theft timeline

The portal's recorded benchmark is a distinct static artifact linked to the accepted `628c371` application / `05fbb2a` ARC evidence. Its historical run IDs and policy digests match the source Markdown. It remains separate from current live results and never promotes a live incomplete result to PASS. ARC's approximately 66% lower issuance application bytes in that workload are shown alongside the identical honest delivery and HTTP exchange counts.

The live holder scene passed and emitted actual controller phase events for preparation, issuance/finalization, copied-token attack, owner proof and a fresh-token duplicate race. Completed phases agreed with independent evidence:

| Phase | Accepted | Refused | Origin arrivals | Gateway claims |
| --- | --- | --- | --- | --- |
| Acquisition | 0 | 0 | 0 | 0 |
| Copied token + attacker key | 0 | 1 | 0 | 0 |
| Owner proof | 1 | 0 | 1 | 1 |
| Twenty duplicate requests, fresh second token | 1 | 19 | 1 | 1 |

Both workers verified ten race requests. Started events remain explicitly pending until their real results arrive. The event timeline contains no token bytes, signing private keys, nonce contents or addresses. It is a presentation of controller observations, not a cryptographically signed audit log.

The focused UI/controller suite passed 22 checks and lab typechecking passed. The final live controller was idle, retaining comparison and theft results. Broader historical network/performance campaigns were not repeated for these presentation/reporting changes.
