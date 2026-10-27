# AIORI-3-HACKATHON-PROJECTS
This repository will contain the code and resources for the AIORI-3 hackathon that will be developed during the AIORI-3

Video Link: https://youtu.be/4pnofXzmptA

## TokenForge — PS-024

Team **A3-PS024-TC119**, Pandit Deendayal Energy University. Krish Sonpal: gateway/replay/security/integration; Mihir Goswami: issuer/client/controller/lab/deployment. Faculty guide: Dr. Kaushal Shah.

The organizer-owned repository and submitted assets above are preserved. All implementation source lives under `src/` as requested by the existing `src/README.md`.

**Current stage: supervised gateway serving implemented; lab integration pending.** Real TLS tests connect challenge generation, blind-issued tokens, Redis single-spend enforcement and a counted protected origin. Both packages validate the shared contract and reproducible builds. The Linux serving process, private control and configured one/two-worker supervision are tested. The complete cross-role reset barrier, deployment isolation and integrated issuer/client deployment remain pending. See the [runtime/controller guide](docs/implementation/GATEWAY_RUNTIME.md). See [gateway status](src/services/gateway/README.md) and historical [G0 status](docs/implementation/G0_STATUS.md).

Read the [technical design](docs/implementation/TECHNICAL_DESIGN.md), [shared contract reference](src/contracts/README.md), and [dependency review](docs/security/DEPENDENCY_REVIEW.md). Executable contract schemas and fixtures define the interfaces shared by the gateway and lab components.

### Local bootstrap checks

Use Node **24.22.1**. On Windows PowerShell use `npm.cmd` if script policy blocks `npm.ps1`; do not weaken execution policy. Other shells use `npm`.

```powershell
npm.cmd ci --prefix src/services/gateway --ignore-scripts
npm.cmd ci --prefix src/services/lab --ignore-scripts
npm.cmd run check:g0
npm.cmd audit --prefix src/services/gateway
npm.cmd audit --prefix src/services/lab
```

Optional independent fixture re-derivation with Python 3: `python scripts/derive-golden-fixture.py --check`.

Docker Desktop must be running Linux containers. From repository root:

```powershell
docker build -f src/services/gateway/Dockerfile -t tokenforge-g0:local .
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 128m --pids-limit 64 tokenforge-g0:local
docker build -f src/services/lab/Dockerfile -t tokenforge-lab-g0:local .
node src/services/lab/scripts/check-image.mjs tokenforge-lab-g0:local
```

The image prints public bootstrap metadata and exits; it does not open ports. Do not run `docker compose up` until Mihir's authoritative configuration exists and has passed its integration checks.

Contract `TF-PS024-1.0.0` is the accepted shared baseline. Both packages maintain independent dependency lockfiles and consume the shared definitions. Observable contract changes require coordinated consumer updates and a versioned change record.
