# Service audit and manual timeline validation

Observed on the Windows demonstration laptop with Linux Docker on 15 November 2026. This adds explicit regional diagnostics; historical baseline retention evidence remains separate.

## Native service records and manual requests

Actual issuer, production two-worker gateway and private origin wrote the audit files. The operator reader inspected them after confirmed Stop, before creating another generation.

| Profile / selected limit | A attempts | A accepted / refused | B access | Issuer rows | Gateway rows | Origin rows |
| --- | --- | --- | --- | --- | --- | --- |
| IP / 2 shared | 3 | 2 / 1 | Refused | 0 | 14 | 4 |
| Ordinary Type2 / 2 each | 3 | 2 / 1 | Accepted | 2 | 17 | 6 |
| ARC / 2 each | 3 | 2 / 1 | Accepted | 2 | 15 | 6 |

The gateway's `claim_accepted` count matched successful resource accesses. IP refusals included `limit-reached`; Type2/ARC replay refusals included `already-spent`. Origin served events matched the independent received/served counters. Issuer events represented two token responses per Type2 enrollment and one credential response per ARC enrollment. IP had no credential issuance. Every parsed audit row matched the expected run ID.

Manual controller timelines contained eight IP or twelve credential-profile lifecycle/action entries, with verified acquisition/access evidence and explicit stop confirmation. These entries are controller observations, distinct from native service-written audit rows.

## Holder theft and race

The final fresh scene passed with two issued tokens: one for owner access and a fresh second for the duplicate race. Native audit records showed:

- One issuer event granting two token responses.
- Attacker proof refusal before the first owner claim.
- Exactly two accepted gateway claims overall: owner plus the race winner.
- Nineteen `already-spent` claim refusals in the twenty-request race.
- Exactly two origin received/served pairs.

The scene's independent evidence reported attack arrivals zero, owner arrivals one and race arrivals one. Both production workers participated in the race (11 and 9 verifications). Native files contained one issuer row, 72 gateway rows and four origin rows, all accepted by the strict reader. The portal ended idle, retaining the result and timeline.

Initial diagnostic trials were retained as incomplete. Two five-token acquisition trials did not confirm client acquisition; native issuer output alone did not establish finalization. A later two-token trial verified acquisition, attack refusal and owner delivery but did not complete the race. The audit-marker setup had been placed after Redis TIME sampled the fixed 60-second policy start, consuming scenario time. Moving all marker/file provisioning ahead of that clock sampling removed this avoidable startup cost; the final run passed without extending the window, nonce lifetime or request/lease deadlines. The exact cause of each earlier transport/finalization uncertainty is not inferred from mixed host/VM timestamps.

The scene now stops as INCONCLUSIVE if acquisition is not confirmed, reporting subsequent theft phases as not tested with null arrivals. It no longer describes missing attempts as measured zero arrivals.

## Reader, privacy and packaging

- Strict formatter/reader tests reject credential fields, addresses, arbitrary errors, malformed JSON, oversized input and unsupported fields.
- The read-only service selector permits only issuer, gateway or origin and a tail length of 1–100; it uses the exact current container identity and one fixed file path.
- The three jury-facing `logs` commands were exercised against real service files. A read concurrent with generation recreation returned unavailable rather than guessing; subsequent reads use a settled generation.
- Focused audit/controller/UI tests and typechecks passed. Earlier focused origin, issuer and coordinator tests, baseline retention regressions and the four real bundle checks passed.
- Docker's raw log driver and baseline sink policy are unchanged. Regional files are explicitly enabled, owner-readable private tmpfs diagnostics targeted at 256 KiB with bounded append slack. They clear on container recreation, may drop records at capacity and are neither durable nor tamper-proof.

See [the operator guide](../lab/DEMO_AUDIT.md) for commands and [security scope](../security/ASSUMPTIONS_AND_EVIDENCE.md) for the added metadata-retention tradeoff. No wider performance or network campaign was repeated for this diagnostic feature.
