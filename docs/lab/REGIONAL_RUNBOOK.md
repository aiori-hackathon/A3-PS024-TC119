# Regional prototype

For native issuer/gateway/origin audit events and the manual controller timeline, see [the demo audit guide](DEMO_AUDIT.md). The read-only `logs --service gateway --tail 15` CLI reads bounded service-written tmpfs diagnostics; Docker's raw logging policy remains unchanged.

## Interactive rate-limit demonstration

Before Start demo, set Shared IP limit (1–50) and Type2 / ARC limit (1–10). These apply only to a newly started window and cannot alter a live policy. For equal aggregate budgets across five clients, use IP = five times the per-client quota; for example 15 shared versus three each. The automated Run comparison always uses 25 versus five each, independent of these fields.

1. IP: choose shared limit 15, Start demo, select A, set Requests to send to 16, then Send requests. Expect 15 accepted and one refused. Select B and Access resource: refused, with zero additional origin arrivals. IP needs no allowance acquisition; that button is disabled and explicitly labelled.
2. Stop demo. Ordinary Type 2: choose per-client limit three, Start demo, acquire A once, then send 16 requests. Expect three accepted and 13 refused. A further access is refused. Select B, acquire once and access: accepted.
3. Stop demo and repeat with ARC and the same per-client limit. Expect the same isolation result using one three-slot credential per client.

The Live request results table reports real attempts, accepted/refused counts, independent origin arrival deltas and evidence state. A refused request clears previously displayed resource content instead of leaving an old delivery on screen. Repeated Acquire is not a refill; the existing allowance remains usable only until spent or expired. Extra demonstration requests reoffer spent credentials to exercise the gateway's rejection path.

The Requests to send input can be edited before startup or acquisition. Its default 26 is not fixed. Send requests remains disabled until an active window and any required acquisition are ready.

Recorded benchmark appears above the live comparison, labelled with its historical date/checkpoint and linked evidence. Use it as a clearly identified fallback when time is short. ARC and Type2 both preserve honest clients' allowances. The recorded ARC advantage is fewer issuance application bytes and one credential for multiple uses, not fewer issuer HTTP exchanges or proven universal speed.

Run theft scene populates a live event timeline for issuance/finalization, copied-token attack, owner access and the fresh-token duplicate race. Show completed evidence rows: attack zero claims/arrivals, owner one, race one. Started rows are pending and contain no private credential contents. Live comparison evidence notes explain incomplete observations instead of hiding them.

Use Node 24.22.1 and Docker Desktop with Linux containers. Provision the existing lab TLS/Redis secrets with `node infra/scripts/provision-secrets.ts` if this is a fresh checkout.

Start the local interface from the repository root,

```powershell
node src/services/lab/src/controller/cli.ts regional --port 4174
```

The command prepares the ARC, lab, gateway and proxy images, then serves the portal at `http://127.0.0.1:4174/`. Open that address, select a profile and start a run. Subsequent runs reuse these images during this controller session. Allow roughly 5–20 minutes for a first build with a healthy connection, with additional time for registry outages. Warm builds are substantially shorter. Keep the controller terminal open.

For a basic demonstration, select ARC, start the run, choose Client A, acquire allowance, then access the research resource. The returned research text travels through the client, shared CONNECT proxy and verification gateway. The page displays the independent private-origin counters and the client's estimated allowance.

Manual demonstrations have a server-defined five-minute allowance and a live countdown. At expiry, authorization is fenced while the portal/controller remains available and displays Allowance expired with retained evidence. Access and acquisition stay disabled. Start new window explicitly creates a fresh generation; Stop demo returns to idle. Neither waiting nor reloading refills an allowance. Automated comparison and holder scenes retain their separately reset 60-second windows. There is no automatic issuance refund after uncertainty.

IP, ordinary Type2 and ARC comparison controls use separately reset experiments with an equal aggregate budget. Holder-bound Type2 has a separate token-copy/owner demonstration. The interface labels incomplete observations explicitly. These optional scenarios are available for manual prototype evaluation.

The portal binds to loopback. Containers publish no service ports. The additional internal `arc_private` bridge connects only issuer, gateway and ARC service. The gateway receives the verification MAC key, and the issuer receives the issuance MAC key. The controller passes secrets through private IPC. Client credential state remains inside client processes and their Rust helper.

Use Ctrl+C in the controller terminal to stop the portal and close the active generation. Emergency fencing remains available through the existing `node src/services/lab/src/controller/cli.ts fence` command.

## Laptop preparation

```powershell
node --version
docker info --format '{{.OSType}}'
npm.cmd ci --ignore-scripts --prefix src/services/gateway
npm.cmd ci --ignore-scripts --prefix src/services/lab
node src/services/lab/src/controller/cli.ts preflight
```

Expect Node 24.22.1, Docker Linux and passing credential/topology checks. On a clean checkout, provision ignored secrets before preflight. Certificates last seven days. To rotate expired certificates, first stop and confirm the old generation, preserve its ignored secrets directory under a dated name, then provision fresh secrets. Keep every key and voucher outside Git and presentation files.

The ARC source must be committed before launch because the image embeds its source revision. Docker builds use locked dependencies and verify the Rust wrapper, corrected P256 implementation and pinned upstream vectors. Registry download failures are build-environment failures. Retry after restoring Docker/network access. A successful HTTP header alone does not prove that a dependency body downloaded completely.

## Evaluator sequence

1. Start ARC, acquire for Client A and access the research brief. Show the returned text and equal independent origin received/served counts.
2. Reset, then run the comparison. Each of IP, ordinary Type2 and ARC has a fresh 60-second experiment, five entitlements and a 25-use aggregate budget. A makes 26 attempts, then B–E each make five. Read each row's state before interpreting its numbers.
3. Explain ordinary Type2 batch enrollment. Each client obtains five tokens in one issuer HTTP exchange. ARC obtains one credential with five presentation slots.
4. Run the separate holder theft scene. Show zero attack arrivals, owner success and one additional arrival for the duplicate race, with both gateway workers participating.
5. Point to gateway claim/refusal counters and independent origin evidence. Missing or uncertain evidence remains INCONCLUSIVE. Timing values are observations from this small workload.
6. Reset and confirm idle. Start again to demonstrate a fresh generation. The server controls experiment creation and window expiry.

ARC malformed-proof, exhaustion and regenerated-slot diagnostics use private fixed client actions and are recorded in the regional validation evidence. The public portal deliberately exposes a small fixed command set.

## Shutdown and retained uncertainty

After reset and controller exit, inspect the exact project inventory.

```powershell
docker ps -a --filter label=com.docker.compose.project=tokenforge --format '{{.ID}} {{.Names}} {{.Status}}'
```

Stopped role containers may remain after a confirmed reset. Redis must have been discarded. For a clean stopped demo project, remove its stopped containers and networks with the profile-aware command below after shutdown is confirmed.

```powershell
docker compose -f infra/compose.yaml --profile regional down --volumes --remove-orphans --timeout 2
```

If the controller reports `shutdown-unconfirmed`, retain its lock and replay state. Restore Docker access, inspect the exact recorded container identities and use the fence command to confirm their process trees have exited. Inspect the lock owner and confirm that controller has exited before recovering an abandoned lock. An absent UI or stale lock timestamp alone cannot establish safe reset. Preserve unresolved state for diagnosis whenever exit cannot be confirmed.

ARC renewals carry only a strictly increasing private sequence. Its receiver owns the 3000ms monotonic lease, and the controller accepts ACKs within 1500ms. Expiry is terminal. The guarantee is measured from the last accepted heartbeat, including any delayed in-flight heartbeat accepted after controller death. Policy UTC windows and observed clock-regression checks still apply. Gateway worker grants keep their shared-OS monotonic original-expiry contract.

## Human rehearsal checklist

- Rehearse live narration and handoffs between Mihir and Krish.
- Confirm venue power, Docker readiness and enough time to warm images before presenting.
- Check the projector/browser scale and the actual laptop's resource budget.
- Perform a physical second-device rehearsal if the evaluator requests it.
- Record participant voice/video with consent. The agent-prepared screen evidence contains no participant narration.
- Preserve the original submitted PDFs and video links. Use the new regional presentation and clearly label recorded fallback evidence.
