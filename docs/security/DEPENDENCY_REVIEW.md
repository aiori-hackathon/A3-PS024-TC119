# G0 dependency review — 24 October 2026

Selected protocol: RFC 9578 Type 2, library `@cloudflare/privacypass-ts@0.9.0`, dependency `@cloudflare/blindrsa-ts@0.4.5`. Engines and real compatibility were checked on installed Node 24; do not rely on the top-level library's older minimum engine when its dependencies require Node 24.

Initial npm audit reported three high entries through one advisory: `sjcl@1.0.8`, its dependent blindrsa package and the parent Privacy Pass package. [GHSA-2w8x-224x-785m](https://github.com/advisories/GHSA-2w8x-224x-785m) concerns ECC public-key point validation; published patch is 1.0.9.

Decision: retain exact Privacy Pass/Blind RSA versions and apply the narrow package-local override:

```json
"overrides": {
  "@cloudflare/blindrsa-ts": { "sjcl": "1.0.9" }
}
```

The installed RSA code imports its vendored `./sjcl/index.js` arithmetic rather than the installed package's ECC API. Inspection found conditional ECC references in general JSON helpers but no affected `ecc.basicKey`/`dhJavaEc` implementation in that vendored file. This override removes the vulnerable **installed dependency**; it does not patch or certify all vendored cryptography. No module source was modified, no advisory was suppressed, and `npm audit fix --force` was not used.

After the override: fresh lock/install and npm audit report zero known vulnerabilities, and the independent public vector plus fresh RSA issuance/finalization/public verification tests pass. Audit results are time-specific database results, not absence-of-defects proof. CI reruns the audit and should fail on new findings, prompting review.

License metadata: Privacy Pass and Blind RSA Apache-2.0; TypeScript Apache-2.0; esbuild and Ajv MIT; Node types MIT. SJCL declares `BSD-2-Clause OR GPL-2.0-only`; use the BSD alternative and preserve distributed license notices. Verify all transitive notices for final distribution; this document does not replace them.

Each consuming package must repeat the override, independent install and audit in its own lockfile. A gateway override does not affect another package.

Library integration constraint: some pinned parsers/serializers use an input's `.buffer` without respecting its offset/length. `libraryBytes()` allocates exact standalone buffers; call it before library parsing and when handing network/Buffer views into protocol objects. Test coverage includes pooled Buffer subviews. Never pass a sliced pooled Buffer directly to the library. Do not reject valid RFC SPKI merely because OpenSSL normalizes its AlgorithmIdentifier when re-exporting it: validate DER framing/key parameters and hash the original RFC encoding.
