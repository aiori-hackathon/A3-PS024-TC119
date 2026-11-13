# G0 lab build/smoke image ONLY; no role entry point, listener or controller yet.
# Build from the repository root: docker build -f src/services/lab/Dockerfile -t tokenforge-lab-g0:local .
# Same base image as the gateway bootstrap: node:24.22.1-bookworm-slim, digest resolved 2026-10-24.
FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS build
WORKDIR /build
# Explicit shared-contract inputs only; gateway source, fixtures and tests never enter this image.
COPY package.json ./package.json
COPY config/tsconfig.base.json ./config/tsconfig.base.json
COPY src/contracts/protocol-v1.json ./src/contracts/protocol-v1.json
COPY src/contracts/lib ./src/contracts/lib
COPY src/contracts/schemas ./src/contracts/schemas
# The host controller (type-checked here, never bundled into a role) imports the public reset barrier utility.
COPY src/security/reset-barrier.ts ./src/security/reset-barrier.ts
COPY src/services/lab/package.json src/services/lab/package-lock.json src/services/lab/.npmrc ./src/services/lab/
WORKDIR /build/src/services/lab
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY src/services/lab/scripts ./scripts
COPY src/services/lab/src ./src
COPY src/services/lab/tsconfig.json ./tsconfig.json
RUN npm run typecheck && npm run build

FROM build AS production-dependencies
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=production-dependencies --chown=node:node /build/src/services/lab/node_modules ./node_modules
COPY --from=build --chown=node:node /build/src/services/lab/dist ./dist
USER node
CMD ["node", "dist/bootstrap.mjs"]
