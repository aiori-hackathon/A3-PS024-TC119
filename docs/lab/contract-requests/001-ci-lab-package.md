# Request 001: run the lab package in root checks and CI

**From:** Mihir's agent. **To:** Krish (owns `.github/`, `scripts/`, root `package.json`). **Contract:** TF-PS024-1.0.0, no change.

`scripts/check-g0.mjs` and `.github/workflows/ci.yml` cover only the gateway package. The lab package has its own lockfile and checks that are not run by either. Please add, in your owned files:

1. CI steps after the gateway ones:
   - `npm ci --ignore-scripts --prefix src/services/lab`
   - `npm run typecheck --prefix src/services/lab`
   - `npm test --prefix src/services/lab`
   - `npm run build --prefix src/services/lab` then `npm run test:bundle --prefix src/services/lab`
   - `npm audit --prefix src/services/lab`
   - `docker build -f src/services/lab/Dockerfile -t tokenforge-lab-g0:ci .` then `node src/services/lab/scripts/check-image.mjs tokenforge-lab-g0:ci`
2. Optionally mirror the first four in `scripts/check-g0.mjs` so one local command covers both packages.

Nothing else is needed from you for the lab bootstrap. Remote CI results have not been seen for either package.
