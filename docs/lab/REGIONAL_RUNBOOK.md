# Regional prototype

Use Node 24.22.1 and Docker Desktop with Linux containers. Provision the existing lab TLS/Redis secrets with `node infra/scripts/provision-secrets.ts` if this is a fresh checkout.

Start the local interface from the repository root,

```powershell
node src/services/lab/src/controller/cli.ts regional --port 4174
```

The command prepares the ARC, lab, gateway and proxy images, then opens the portal at `http://127.0.0.1:4174/`. Select a profile and start a run. Subsequent runs reuse these images during this controller session.

For a basic demonstration, select ARC, start the run, choose Client A, acquire allowance, then access the research resource. The returned research text travels through the client, shared CONNECT proxy and verification gateway. The page displays the independent private-origin counters and the client's estimated allowance.

Each experiment has a server-defined 60-second window. Expiry closes the generation. Reset ends the controlled experiment and confirms shutdown before another experiment can start. Starting a new experiment provisions fresh keys, state and entitlements. There is no automatic issuance refund after uncertainty.

IP, ordinary Type2 and ARC comparison controls use separately reset experiments with an equal aggregate budget. Holder-bound Type2 has a separate token-copy/owner demonstration. The interface labels incomplete observations explicitly. These optional scenarios are available for manual prototype evaluation.

The portal binds to loopback. Containers publish no service ports. The additional internal `arc_private` bridge connects only issuer, gateway and ARC service. The gateway receives the verification MAC key, and the issuer receives the issuance MAC key. The controller passes secrets through private IPC. Client credential state remains inside client processes and their Rust helper.

Use Ctrl+C in the controller terminal to stop the portal and close the active generation. Emergency fencing remains available through the existing `node src/services/lab/src/controller/cli.ts fence` command. Prototype UI and full scenario evaluation remain manual acceptance steps.
