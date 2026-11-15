# Regional validation checkpoint

The finalization code checkpoint is `628c371`, with ARC image source identity `05fbb2a`. On 15 November 2026 the complete deployed three-profile comparison and holder scene passed. ARC private diagnostics, real window expiry, fresh generation and Redis-loss refusal also completed, followed by strong fenced closure. Exact aggregate evidence, scoped historical failures and commands are in [regional final evidence](REGIONAL_FINAL_EVIDENCE.md).

The known lease, bundle and teardown blockers are fixed. The network checker passes 177/177, including cleanup of a pre-existing exited optional ARC container. G0 passes, and the two native Linux consumer tests execute with zero skips. The updated runbook, narration and new regional presentation accompany this checkpoint. Human venue, voice/video participation and physical-device rehearsal remain pending.

## ARC lease diagnosis and correction

The original heartbeat-20 receiver branch was unavailable in the historical capture. A controlled native reproduction of the old expiry-bounds branch supplied an expiry 10 seconds beyond the sender's current time and received `invalid-input`, with safe diagnostics identifying `lease-expiry-bounds`. It establishes the old rejection branch under that controlled condition. The exact cause of the earlier deployed heartbeat-20 refusal remains unconfirmed.

Private renewals now carry only operation and the strict next sequence. The receiver owns a 3000ms monotonic deadline. Existing expiry wins before renewal and cannot be revived. The controller accepts ACKs within 1500ms using monotonic checks before and after decoding. EOF, window checks, observed wall-clock regression and post-cryptography liveness remain enforced. Expiry is bounded from the last accepted heartbeat, including delayed in-flight work accepted after controller death. Gateway worker original-expiry grants retain their existing shared-OS monotonic contract.

Focused tests cover sender wall-clock offsets, replay/skip sequence refusal without deadline refresh, terminal expiry, EOF, window end and post-crypto expiry. Both private consumers were updated. Public ARC issue/verify authentication and proof bindings remain intact.

## Historical deployed results before finalization

The live portal checks below ran on the integrated `e3a4bbc` application, including gateway compatibility fix `21c5507`, on a Windows host with Linux Docker containers. The subsequent `9fb5386` changes address terminal startup uncertainty and topology readiness; their focused regression checks passed.

| Check | Observed result | Scope |
| --- | --- | --- |
| ARC resource access | One admitted client acquired a credential and received the 1,024-byte resource; origin received/served and gateway claim counters all equalled one | Actual client, issuer, Rust service, gateway, Redis, proxy and origin |
| IP comparison | 25 total accepted uses, zero honest-client uses after the abusive client; 46 source observations; both workers participated | One separately reset equal-budget run |
| Ordinary Type2 comparison | 25 total accepted uses, including 20 honest-client uses after the abusive client's five; 46 workload source observations; both workers participated | One separately reset equal-budget run; batch enrollment used five total HTTP interactions |
| Holder theft/owner | Attack caused zero origin arrivals; owner caused one | Real per-token key and nonce proof, with independent origin deltas |
| Holder duplicate race | Exactly one additional origin arrival; worker verification deltas were 10 and 10 | Twenty duplicate requests across two production worker processes |
| ARC malformed proof | Refused with zero origin arrivals; a subsequent valid owner request succeeded in the diagnostic run | Actual Rust verification before shared claim |
| ARC exhausted client | After the owner's first accepted use, 26 abuse attempts produced four more accepts and 22 refusals; another client's request still succeeded | Independent origin count increased from five to six for the honest client |
| ARC regenerated copied slot | The copied slot won once; reoffering the same slot through the owner's wallet was refused without another origin arrival | Does not claim ARC holder binding or protection against first-use credential theft |

The complete three-profile comparison **did not pass**: ARC supervision later returned an authenticated private-control `invalid-input` refusal and the controller closed the run as uncertain. The partial passing rows are retained; missing ARC completion is not promoted to PASS. A separate ARC diagnostic also closed on the same supervision refusal. No performance ranking is inferred from these single runs.

## Focused checks and boundaries

- The delayed-Compose and delayed-link cancellation tests pass. The latest terminal-uncertainty test refuses new start/reset/access commands after unconfirmed creation, retaining ownership and avoiding another Compose operation or Redis discard.
- All nine focused readiness/controller regression tests passed at `9fb5386`. Actual local preflight then accepted the intended topology, credentials, runtime versions and Linux engine. Preflight explicitly does not substitute for live isolation.
- The live network checker passed 176 network/hardening checks, but its final cleanup assertion failed because an exited optional ARC container remained. Profile-aware cleanup removed that container and an explicit project inventory confirmed no remaining test containers. The unmodified checker still needs its profile-aware teardown fix before the whole command is recorded as PASS. The ARC process is inactive during that check; its additional bridge-membership proof has that stated scope.
- The integrated `check:g0` reached a failing lab bundle allowlist assertion: the build correctly includes `regional-helper.mjs`, while the older test expects the seven baseline bundles. Typechecking and preceding functional suites passed, but the overall command remains FAIL until the allowlist is aligned with the already updated production-image checker and rerun.
- The earlier native consumer gate passed both required tests without skips: actual Rust service/helper/issuer/client through the labelled substitute ARC gateway, and actual holder client/issuer/gateway/restricted Redis/test origin. This is separate from the complete deployed ARC controller path.

Those historical blockers were ARC supervision interoperability, the lab bundle-test allowlist and profile-aware network-check teardown. Their fixes and new evidence are recorded above. The earlier incomplete trials retain their original scope and outcome.

## Reproduction entry points

```powershell
npm.cmd run check:g0
npm.cmd run test:regional-integration --prefix src/services/gateway
node scripts/check-regional-consumers.mjs
node src/services/lab/src/controller/cli.ts preflight
node infra/scripts/check-network.mjs
node src/services/lab/src/controller/cli.ts regional --port 4174
```

In the portal, use separately reset comparison and holder-theft scenes. Inspect independent received/served counts, gateway claims, worker participation and scoped PASS/FAIL/INCONCLUSIVE outcomes. Do not export client credentials/proofs or repurpose baseline saved-report schemas to certify missing regional evidence. Raw private diagnostics are not repository deliverables.
