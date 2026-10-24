# G0-001 — Mihir's independent consuming bootstrap

Owner requested: Mihir's agent. Status: pending. Read root `AGENTS.md`, mapped plan v1.2, `MIHIR_AGENT_HANDOFF.md`, `src/contracts/README.md` and dependency review first. Do not start an independent replacement architecture.

## Files you create/review

Create your `src/services/lab/` package/lockfile, build tooling, smoke entry/test and Dockerfile; create `infra/` only as needed for your environment checks. Do not modify root/CI/contracts/gateway. All actual issuer/client/controller/origin roles remain separate runtime entry points, even though they share your one package. Add review notes/results under `docs/lab/` and contract change requests under `docs/lab/contract-requests/`.

## G0 proof required

1. Fetch/check out the reviewed bootstrap commit from Krish's branch, then branch from that candidate/integration commit. Record its hash and contract version in your review. Do not use the previous root-level source paths.
2. Independently derive the context/challenge/config/spend fixture once (not by simply calling the TS helper under test). Compare expected bytes/digests with `src/contracts/fixtures/policy-golden.json`; then import shared helpers normally.
3. Clean-install/typecheck/test/build your package with its own lockfile. Pin the same actual Node 24 runtime and compatible owner-local tools. The gateway's transitive override does not apply to you: use the scoped `@cloudflare/blindrsa-ts -> sjcl:1.0.9` override and run your audit/vectors too.
4. Prove real Type 2 request creation/blinding, issuer signing, finalization, public-only verification and exact lengths. Copy network/Buffer views into standalone `Uint8Array`s before using pinned library parsers/objects. Never retain fixture private keys/live keys in files.
5. Build your image from root context, explicitly COPY only your package/shared sources, exclude fixtures/tests/keys from runtime, and confirm independent bundling without gateway private imports/root dependency leakage.
6. Review manifest/control/report schemas against your controller requirements. Initial null digest, enable/lease initialization, bounded sealed provisioning, asynchronous responsive FENCE/STATUS, worker limits and complete evidence must remain compatible. Schema alone does not implement the state machine.
7. Send your branch/commit, exact checks/results, independent fixture comparison and any required contract request to Krish. G0 closes only after both packages and review agree; then G1 can proceed in separate folders.

For your stacked G0 bootstrap branch, run `node scripts/check-ownership.mjs --owner mihir --base <Krish-bootstrap-commit>` so inherited K files are not mistaken for your changes. After G0 merges and you branch from the updated default branch, the usual `origin/main` base applies. The checker also includes uncommitted/untracked files; keep unrelated work out of that checkout.

## CODEOWNERS — user will complete

Edit `.github/CODEOWNERS`: replace `MIHIR_LOGIN` in its five commented M entries with the actual GitHub login and remove the leading comment marker. Example form: `/src/services/lab/ @actual-login`. Keep the owner split for `infra/` and the three M docs folders. Commit this integration-file update through Krish/the user; Mihir's agent requests it rather than editing K-owned files. Both accounts need repository write access; ownership transfer is already complete and must not be repeated.

Do not merge or overwrite the default branch just to start. Review the candidate first, merge G0 through the agreed workflow, then branch G1 work from that accepted baseline.
