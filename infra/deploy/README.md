# Private Linux host reproduction

Use a separate quiet Linux host with Docker Engine 28.0.4 or newer, Compose 2.38.2 or newer, OpenSSL 3 for component TLS tests, Git, and exactly the Node patch in `.node-version` (24.22.1). Provisioning itself uses Node crypto, not the OpenSSL executable. These floors cover the GitHub Ubuntu runner and the newer development Docker Desktop versions. Install those host tools through your host's normal administration process. The account needs Docker access; it is a trusted host/controller account. Clone this repository and check out the team's selected commit on the host. Do not copy `.runtime`, secrets, tokens, snapshots or dependency directories from another machine.

From that checkout:

```sh
bash infra/deploy/lab.sh setup
npm run check:g0
bash infra/deploy/lab.sh network
bash infra/deploy/lab.sh demo
bash infra/deploy/lab.sh security
bash infra/deploy/lab.sh performance-smoke
bash infra/deploy/lab.sh performance
bash infra/deploy/lab.sh summary artifacts/performance-<timestamp>.json
bash infra/deploy/lab.sh verify artifacts/security-<timestamp>.json
bash infra/deploy/lab.sh viewer artifacts/security-<timestamp>.json
```

Every run writes a new timestamped report. Keep failed/incomplete reports; do not replace them with a successful retry under the same name. `setup` refuses unsupported Node and does not overwrite existing secrets. TLS certificates last seven days. To rotate, fence first, move the existing `.runtime/secrets` aside into private ignored storage, then run setup again. Node and certificate checks are read-only. POSIX checks enforce owner-only secret directories and no group/other file writes; file mode 0644 is intentional inside 0700 directories so role UIDs can read explicitly mounted files.

All ten Compose services remain on five internal bridges. Role control, Redis and the private origin have no host ports. The viewer listens only on host loopback. From a presentation machine use `ssh -N -L 4173:127.0.0.1:4173 <private-host>` and open `http://127.0.0.1:4173`. Never publish service or control ports to make the demo convenient. Preflight checks declarations and obvious interface/Docker subnet overlap; it cannot see every VPN route. The network command provisions its own temporary deployment and checks live reachability with positive controls. Run it only while no controller owns an active experiment.

Emergency stop and cleanup:

```sh
bash infra/deploy/lab.sh fence
bash infra/deploy/lab.sh cleanup
```

Cleanup stops if inventory/fencing is unknown. Normal controller runs use the stronger incarnation-bound reset barrier and confirmed process/container exit before Redis discard. Do not flush Redis or delete the project lock to bypass an unknown shutdown. If a lock remains, restore Docker access, fence and confirm old roles, then inspect/remove only that stale `.runtime/project.lock` deliberately.

The team must still supply the separate physical host and venue access. Reproduce setup from a fresh checkout, retain the tested commit and sanitized reports, inspect the viewer over SSH, rehearse the CLI Access → Attack → Recovery sequence in [DEMO](../../docs/demo/DEMO.md), and verify the actual venue's network/SSH constraints. These human rehearsals are not implied by local Docker Desktop or CI results. Presentation writing, video and organizer submission remain outside this tooling.
