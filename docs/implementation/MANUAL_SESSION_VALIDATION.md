# Manual demo session validation

Observed on 15 November 2026 on the Windows demonstration laptop with Linux Docker. This supplements the prior regional acceptance; historical 60-second comparison evidence remains scoped to its original checkpoint.

## Behavior

- An operator-started manual ARC run installed a five-minute authenticated window and delivered the 1,024-byte resource.
- After more than 60 seconds, the same run remained active with its original run ID, one gateway claim, one received request and one served resource.
- After the five-minute deadline and confirmed closure, the controller remained reachable and reported `expired`, retaining the profile, deadline and aggregate evidence.
- An explicit access command after expiry returned refused and retained `expired`, with no new allowance or change in the retained counters.
- Starting a new window and stopping it are separate operator actions. New windows receive a fresh run identity; Stop demo returns to idle.

The portal/controller remains available after expiry. The expired authorization generation is fenced; keeping the page available does not mean credentials remain usable or cryptographic supervision is disabled.

## Focused checks

- 28 contract, canonical-wire, replay-adapter, client and controller checks passed.
- 13 issuer, startup and holder-verifier checks passed.
- 10 portal checks passed, including execution of the actual frontend module with an expired status, retained evidence, disabled access, explicit new-window command and explicit stop command.
- Gateway and lab typechecks passed; generated schemas and independent Python framing/MAC fixtures matched.
- ARC image verification ran the Rust policy/adapter/runtime checks and preserved the pinned upstream verification stages before building release binaries. The new Rust check accepts only 60,000 and 300,000 milliseconds.
- All seven pre-existing actual-Redis checks passed. The added duration check initially expected the wrong replay result label; after correcting that assertion to the existing `ALREADY_SPENT` ABI, the focused duration check passed for both durations. It verifies atomic spending, duplicate refusal, exact retention, unsupported-duration refusal without a spend, and terminal expiry.

The first deployed attempt exposed the remaining 60-second-only Redis initialization guard. Regional replay revision 2 corrects initialization, snapshot and claim together. Temporary fixed-label startup diagnostics were removed after locating the failure. No baseline Lua bytes or key/argument ABI changed.

This change does not implement the separately requested staged rate-limit walkthrough or crash recovery. Automated comparison and holder scenarios continue to select the 60-second duration; a new full performance/network campaign was not run for this presentation-lifecycle change.
