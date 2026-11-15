# Reusable theft demonstration

The portal now separates **Prepare theft demo** from **Run theft test**. Preparation starts one five-minute holder-bound Type2 generation and acquires ten tokens for Client A once. Each token has its own holder key. Five tests consume distinct two-token pairs; repeating never recreates services, reissues tokens or extends the window. Manual acquisition/access is refused while this inventory is reserved. Stop and expiry use the existing generation cleanup. A failed or incomplete test closes the generation rather than attempting a refund. The one-shot `run_theft_scene` API retains its original automatic cleanup.

## Live laptop verification

Run `d1862049b595bf030a3296e536c4a931`, original expiry `2026-11-15T20:19:15.448Z`:

| Test | State | Attacker origin arrivals | Owner arrivals | Race arrivals | Race worker attempts |
|---|---|---|---|---|---|
| 1 | PASS | 0 | 1 | 1 | 10 / 10 |
| 2 | PASS | 0 | 1 | 1 | 11 / 9 |
| 3 | PASS | 0 | 1 | 1 | 11 / 9 |
| 4 | PASS | 0 | 1 | 1 | 11 / 9 |
| 5 | PASS | 0 | 1 | 1 | 14 / 6 |

Each race sent twenty copies of one prepared valid request and had one accepted request and nineteen refusals. All five tests remained Active on the same run ID, revision, original expiry and ten container identities. Independent cumulative origin received/served counters advanced by two per test and ended at ten. A sixth test was refused while services remained active. Explicit Stop returned Idle and cleared the prepared session. Run without preparation, including after Stop, was refused without starting a new generation.

Focused controller, portal transport and UI tests cover preparation gating, exact command shapes, repeat controls, exhaustion, unchanged countdown, reserved inventory controls and retained lifecycle safeguards. Existing holder-client coverage exercises distinct per-token keys, attacker refusal without consuming the owner's token, and a fresh-token race. TypeScript checking passed. This change reuses the existing manual-window expiry path; the live check above stopped explicitly before expiry and does not constitute another timed-expiry test.

## Presentation

1. Stop the previous manual demo.
2. Prepare theft demo once; allow its startup and issuance to finish.
3. Run theft test and show PASS, zero attacker arrivals, one owner arrival and one race winner.
4. Run theft test again to show the same checks without another container startup.
5. Show the original allowance countdown and remaining test pairs. Stop demo when finished.

Native service events remain available through `logs --service gateway --tail 100`. In this reusable session they share one run ID; use the current UI timeline and event timestamps to distinguish attempts. Retention remains bounded, and a tail snapshot is not the full session history.
