# G0 contract build/smoke image ONLY; not a serving gateway yet.
# node:24.22.1-bookworm-slim, multi-platform image digest resolved 2026-10-24.
FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS build
WORKDIR /build
COPY package.json ./package.json
COPY config/tsconfig.base.json ./config/tsconfig.base.json
COPY src/contracts/protocol-v1.json ./src/contracts/protocol-v1.json
COPY src/contracts/lib ./src/contracts/lib
COPY src/contracts/schemas ./src/contracts/schemas
COPY src/services/gateway/package.json src/services/gateway/package-lock.json src/services/gateway/.npmrc ./src/services/gateway/
WORKDIR /build/src/services/gateway
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY src/services/gateway/scripts ./scripts
COPY src/services/gateway/src ./src
COPY src/services/gateway/tsconfig.json ./tsconfig.json
RUN npm run typecheck && npm run build

FROM build AS production-dependencies
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=production-dependencies --chown=node:node /build/src/services/gateway/node_modules ./node_modules
COPY --from=build --chown=node:node /build/src/services/gateway/dist ./dist
USER node
CMD ["node", "dist/bootstrap.mjs"]
