# G1 progress: M01 issuer and M02 client

**Branch:** `mihir/g1-issuer-client`, from `origin/main` at `234f5e4`
**Contract:** `TF-PS024-1.0.0`, unchanged. No contract request is needed for this slice.
**Scope:** `src/services/lab/` only.

## What exists

| Area | Files (under `src/services/lab/src/`) | State |
|---|---|---|
| Sealed provisioning | `inventory.ts`, `issuer/vouchers.ts`, `client/vouchers.ts` | Bounded, ordered, duplicate-checked, sealed. Used for issuer digests and client plaintext vouchers |
| Issuer issuance | `issuer/issuance.ts`, `issuer/admission.ts`, `issuer/directory.ts`, `issuer/server.ts` | Real blind issuance over TLS 1.3 with the plan's status ordering and limits |
| Issuer lifecycle | `issuer/control.ts` | Key creation, prepare, provision, ready, enable with lease, heartbeat, fence, status, report |
| Control transport | `control-server.ts` | Newline-delimited JSON on a private local socket; async dispatch; reserved FENCE/STATUS path |
| Client | `client/client.ts`, `challenge.ts`, `tunnel.ts`, `inventory.ts` | CONNECT then pinned TLS 1.3; strict challenge parse; one library `Client` per issuance; memory-only inventory |
| Client lifecycle | `client/control.ts` | PREPARE, PROVISION_CLIENT, READY, ENABLE, async RUN_SCENARIO (one at a time), FENCE, STATUS, REPORT. Only `healthy-flow` exists; other frozen names refuse with `ILLEGAL_STATE` rather than fake a result |
| Process entry points | `roles/issuer.ts`, `roles/client.ts`, `roles/control-helper.ts`, `roles/common.ts` | Three built bundles plus the G0 smoke bundle. Helper reads validated requests on stdin and prints validated replies; fixed error text; no echo |

Tests: 64 pass on Node 24.18.0 (host, one POSIX-only socket-mode test skipped) and 65 of 65 on `node:24.22.1-bookworm-slim`; `test:bundle` passes 4 of 4 on both. Typecheck, `npm run build`, the image check and `npm audit` are clean.

## Behaviour that is tested

- **Order of refusals:** closed 503, wrong media type 415, protocol-invalid 422 (before any voucher is consumed), generic 403, signing. Framing errors are 400 (missing, duplicate or `+` Content-Length; Transfer-Encoding), 413 above 4096 declared, 431 for more than 32 headers or 8192 bytes, 405 and 404.
- **Voucher use:** a voucher authorizes one signing. Concurrent use of one voucher yields one 200. A signing failure returns a fixed 500 and the voucher is not refunded. A duplicate voucher header consumes nothing.
- **Lifecycle:** a closed run cannot be re-created, re-prepared or re-enabled. FENCE with no run does not latch. Repeat ENABLE acknowledges without renewing. Expiry is judged before any renewal, so a late heartbeat cannot revive a run. A watchdog closes admission with no further message (3.4 s real-time test). A failed listener bind faults the run. PREPARE must describe the key this process generated.
- **Client trust:** wrong CA, wrong server name, refused or dirty CONNECT, redirects, oversize or stalled replies all fail closed. Only the two lab hostnames on 443 can be dialled. A forged issuance response never enters the inventory.
- **Five clients, two tokens each,** through one proxy against the real issuer role. Token replay is refused by the stub gateway.

## Findings

1. **Node `Agent.maxSockets` does not bound tunnels when `createConnection` is asynchronous.** A socket is counted only after the callback fires, so six parallel requests opened six tunnels. The client now gates in-flight exchanges per destination at the manifest limit (2 issuer, 24 gateway for the security profile). A test asserts peak concurrent tunnels.
2. **The library's `WWWAuthenticate` parser is lenient** (it strips quotes anywhere and keeps the last duplicate). The client checks syntax itself and uses the library only to decode the already-validated challenge bytes. The challenge header format `PrivateToken challenge="…", token-key="…"` matches what the gateway branch emits.
3. **A client accepts a challenge only for the pinned key and run, and only for the current, previous or next epoch.** This is a choice of mine, not in the plan. The scenario harness can still present wrong-context tokens through `redeemWire`.
4. **Issuance sign failure is 500 `issuance-failed`.** The plan says "fixed safe failure result" without a status. Please say if the gateway side expects something else.
5. **REPORT from the issuer carries only `issuance_successes` and `issuance_failures`.** Issuance latency histograms are not recorded yet.

- **Built-process test:** the built `issuer.mjs` is started with only a socket path, a secrets directory and a bind address, then driven through the built `control-helper.mjs` from STATUS discovery to a real HTTPS issuance and a FENCE. The process writes nothing to stdout or stderr. A malformed request makes the helper exit 1 with `control-helper-failed` and no echo.
- **Client scenario control:** a stalled scenario does not block STATUS or FENCE; FENCE aborts it, waits for it to settle and returns no result. A scenario that throws is reported as FAIL with a fixed label.

## Environment names read by roles

`PS024_CONTROL_SOCKET` (default `/run/ps024/control.sock`), `PS024_SECRETS_DIR` (default `/run/secrets`), `PS024_BIND_ADDRESS` (default `127.0.0.1`, so an unconfigured issuer is never exposed) and `PS024_LISTEN_PORT` (default 443). None carries a secret. Compose (M03) must set the bind address to the planned interface.

## Not done yet

- The Dockerfile runtime `CMD` is still the G0 smoke bundle; Compose selects the role by command.
- Compose, the real proxy and Redis now exist (see `INFRA.md`); the real gateway has not run in them, and the proxy and gateway inside the library tests are still stubs.
- Scenarios other than `healthy-flow` and report assembly (M05); controller, lock and supervision (M04).
- The issuer REPORT has no latency histograms yet.
