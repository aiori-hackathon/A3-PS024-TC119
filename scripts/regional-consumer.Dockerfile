ARG ARC_IMAGE=tokenforge-arc:interop
FROM ${ARC_IMAGE} AS arc
FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205
WORKDIR /work
COPY package.json ./package.json
COPY config/tsconfig.base.json ./config/tsconfig.base.json
COPY src/contracts ./src/contracts
COPY src/security/reset-barrier.ts ./src/security/reset-barrier.ts
COPY src/services/lab/package.json src/services/lab/package-lock.json src/services/lab/.npmrc ./src/services/lab/
RUN npm ci --ignore-scripts --no-audit --no-fund --prefix src/services/lab
COPY src/services/gateway/package.json src/services/gateway/package-lock.json src/services/gateway/.npmrc ./src/services/gateway/
RUN npm ci --ignore-scripts --no-audit --no-fund --prefix src/services/gateway
COPY src/services/lab/src ./src/services/lab/src
COPY src/services/lab/test ./src/services/lab/test
COPY src/services/gateway/src ./src/services/gateway/src
COPY src/services/gateway/test/holder-client-integration.test.mjs ./src/services/gateway/test/holder-client-integration.test.mjs
# The Node test's expected executable locations contain the compiled release binaries.
COPY --from=arc /usr/local/bin/arc-service ./src/services/arc/target/debug/arc-service
COPY --from=arc /usr/local/bin/arc-client-helper ./src/services/arc/target/debug/arc-client-helper
ARG TF_ARC_SOURCE_REVISION
ENV TF_ARC_RUNTIME_TEST=1 TF_ARC_IMPLEMENTATION_REVISION=${TF_ARC_SOURCE_REVISION}
RUN node -e "if(!/^[0-9a-f]{40}$/.test(process.env.TF_ARC_IMPLEMENTATION_REVISION))process.exit(1)" \
    && test -x src/services/arc/target/debug/arc-service \
    && test -x src/services/arc/target/debug/arc-client-helper \
    && test -f src/services/lab/test/regional-arc-runtime.test.ts
USER node
CMD ["node", "--test-isolation=none", "--test-concurrency=1", "--test", "src/services/lab/test/regional-arc-runtime.test.ts", "src/services/gateway/test/holder-client-integration.test.mjs"]
