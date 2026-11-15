# Regional CI and local checks

The `Bootstrap checks` workflow has `contracts-and-crypto` followed by `deployed-demo`. The first job runs compatibility, replay, production regional gateway tests, required native ARC/holder consumers, fixture derivation, audits and minimal-image checks. Native consumer acceptance requires every required test to execute with zero skips. The second job provisions fresh ignored secrets and runs preflight, the network checker and deployed baseline demo/security/performance-smoke reports. Its artifacts pass the existing safe-report collector.

Local affected checks and actual regional deployment evidence are recorded in [the final evidence](REGIONAL_FINAL_EVIDENCE.md). The complete regional portal comparison, holder scene and private diagnostics were exercised on the intended laptop. The deployed baseline CI reports have a separate scope.

ARC source must be committed before its image or native consumer gate is built. The image embeds the latest ARC-path commit. Locked dependencies, corrected-fork tests and pinned upstream vectors run in the build. Cargo registry and Git caches are BuildKit cache mounts shared across source revisions. Registry/Git transports use HTTP1 and Git CLI. A fresh runner still needs network access to the pinned sources.

Use the final pushed commit's workflow run to judge remote status. A previous commit's green result and local passes each have their own scope. Workflow links and final integration state are supplied with the handover. Remote `05fbb2a` completed both jobs successfully before the final documentation/package commit.
