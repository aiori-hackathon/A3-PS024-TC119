# Server audit logs for the live demonstration

The regional demo has two complementary views:

- The website's **Manual demo event timeline** describes actual controller operations and their independently observed results.
- The terminal's **server audit records** are written by the issuer, gateway worker and protected origin themselves. They are not reconstructed from the website timeline.

## Show the jury

Start a new regional demo, acquire when needed, and make a few access attempts. Open a second PowerShell terminal in the repository root; leave the controller running.

```powershell
node src/services/lab/src/controller/cli.ts logs --service issuer --tail 5
node src/services/lab/src/controller/cli.ts logs --service gateway --tail 15
node src/services/lab/src/controller/cli.ts logs --service origin --tail 5
```

The output is validated JSON lines. The first line identifies the service and warns that this is bounded diagnostic history. Audit rows contain UTC timestamp, process ID, service, event and run ID, with optional profile, HTTP status, count or fixed refusal reason. The common run ID connects the services within the same experiment; process IDs distinguish gateway workers.

Different workers can append slightly out of timestamp order. Host and VM timestamps also need not establish precise ordering. Use the run binding, event semantics, independent counts and each phase's verified outcome rather than inferring exact cross-process latency from these lines.

| Service | Events to explain |
| --- | --- |
| Issuer | `issuance_granted` after producing the response; `issuance_refused` when issuance fails |
| Gateway | `proof_verified` or `proof_refused`; IP uses `identity_verified`; `claim_accepted` or `claim_refused`; `origin_forward_started`; response-write completion |
| Origin | `resource_received`, `resource_served` or `resource_refused` |

`claim_refused` can show fixed reasons such as `limit-reached` for an exhausted IP budget and `already-spent` for a repeated token/slot. A claim may succeed even if its later response is lost; the audit does not promise exactly-once delivery.

For ARC, issuer counts represent issued credentials; for Type2 they represent individual token responses. A credential's presentation quota is shown in the server policy on the website. The current audit reader covers issuer, gateway and origin; it does not claim to expose the Rust service's internal transcript.

The scripted holder theft scene now requests exactly two tokens: one for the owner phase and a fresh second token for the duplicate race. This removes unused signing work from that demonstration. The ordinary comparison remains 25 shared versus five per entitlement, and manual per-client limits remain operator-selected. No cryptographic or network deadline is extended.

## Retention and privacy

The controller enables this sink only for fresh supervised regional demos, before public admission. The baseline remains unmarked and does not write these records. Each selected service writes `/run/ps024/demo-audit.jsonl` in its private existing tmpfs, with owner-only file permissions. The target limit is 256 KiB per container, with bounded concurrent-append slack. Once full, new diagnostic records are dropped; authorization continues normally. Logs are therefore not a complete durable or tamper-proof audit trail.

Sink preparation runs while roles are fenced, before Redis TIME starts the allowance window. Diagnostic setup must not consume the timed scenario's usable window. Diagnostic writes still have overhead; do not compare logged live timings against an unlogged recorded run as a controlled speed result.

No raw token, signature, voucher, nonce contents, private key, authorization header, IP address, arbitrary URL or arbitrary exception message has a supported field. The reader validates every record before printing and refuses malformed/unknown fields rather than echoing raw content. Run IDs, timestamps and process IDs are still diagnostic metadata; this is an explicit presentation-mode retention choice.

Confirmed Stop normally leaves role containers alive but fenced, so their audit files remain readable until the next experiment recreates those containers. New containers or Compose cleanup remove the tmpfs records. Exporting terminal output to a host file would create a separate copy whose retention the operator must manage; the reader does not do so automatically.

## Why this is a dedicated logs command

Docker's raw `logs` command remains disabled by the existing `logging: driver: none` policy. The gateway serving process is launched through private `docker exec` IPC, so changing the container's logging driver alone would not capture its events. The command above reads only the fixed service-written audit file from an exact current container identity. It grants no arbitrary command, path or container selector.

If the reader reports `audit-unavailable`, start a new demo using the updated controller and allow startup to finish. Containers created before the feature was enabled have no audit file. Services with no relevant requests can validly return zero audit rows; for example IP mode does not issue credentials. `--tail` accepts 1–100.

Use independent origin counters, gateway claims and client outcomes as the acceptance evidence. The logs help explain those decisions; logging failure does not refund a spend or change authorization.
