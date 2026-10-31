# Lab infrastructure (M03)

**Contract:** `TF-PS024-1.0.0`, unchanged. **Owner paths:** `infra/`, `src/services/lab/`. No file outside them was edited.

`infra/compose.yaml` is the single authoritative Compose file. It defines the proxy, issuer, gateway, Redis, private origin and clients A to E on five internal bridges. It starts every role fenced. Nothing serves a run until a controller (M04) drives it.

## Use

```
node infra/scripts/provision-secrets.ts     # once; writes git-ignored .runtime/secrets/, refuses to overwrite
node infra/scripts/check-network.mjs        # boundaries, with inert listeners standing in for role processes
node infra/scripts/check-roles.mjs          # the real issuer, origin and client containers, through the proxy
```

Both checks bring the stack up, test, and tear it down (`--keep` leaves it up). `check-network.mjs --mutate-leak` deliberately joins a client to the Redis network and must fail; it is the self-test for the checker.

## Layout

| Network | Subnet | Members |
|---|---|---|
| `client_proxy` | 172.28.10.0/24 | proxy .2, clients A to E at .11 to .15 |
| `proxy_issuer` | 172.28.20.0/24 | proxy .2, issuer .10 (`issuer.lab.test`) |
| `proxy_gateway` | 172.28.30.0/24 | proxy .2, gateway .10 (`origin.lab.test`) |
| `gateway_replay` | 172.28.40.0/24 | gateway .20, Redis .10 |
| `gateway_origin` | 172.28.50.0/24 | gateway .20, private origin .10 (`protected-origin`) |

All five are `internal`, IPv6 off. No host port is published and the proxy has no loopback mapping, because publishing from an internal network does not work; the controller will reach roles with `docker exec`.

## Controls

- **Every container:** read-only root, all capabilities dropped, `no-new-privileges`, no restart, `logging: none`, pids and memory limits, non-root user, private `/run/ps024` tmpfs (mode 0700) for the control socket.
- **Proxy (tinyproxy 1.11.2, Alpine 3.22, both pinned):** listens only on the client address; source ACL `172.28.10.0/24`; `ConnectPort 443`; a default-deny filter over the whole `host:port` string, anchored to exactly `issuer.lab.test:443` and `origin.lab.test:443`. Raw IPs, other ports, lookalike names and plain-HTTP proxying all fail.
- **Redis (7.4, digest pinned):** bound to its network address, no persistence (and `/data`, which the image declares a VOLUME, is a tmpfs so Docker creates no anonymous volume; found by the S15 retention audit), diagnostic retention off, `default` user off. Only a controller account exists at start; the gateway account is created by the controller. It has a private local socket for the controller.
- **Secrets:** each role mounts only its own files. Issuer: TLS cert and key. Clients: lab CA certificate. Redis: ACL file. Gateway, proxy and origin: none. The gateway's TLS key and Redis password are not mounted; the controller passes them over stdin, as Krish's `GATEWAY_RUNTIME.md` specifies. The CA private key is never written to disk. Files are 0644 inside a 0700 directory so a container UID different from the host user can read them; that is a lab trade-off for a single-user host.

## What the checks prove

`check-network.mjs`: 158 of 158. Reachability from inside containers, including positive controls for each probe type, DNS isolation, 16 refused CONNECT targets plus 3 refused plain-proxy requests, container hardening, exact network membership and secret mounts per role, forwarding and IPv6 off, no published ports, Redis posture (unauthenticated clients refused, slow log, ACL log, latency history, keyspace events and persistence all off). With `--mutate-leak` it reports three failures and exits 1.

`check-roles.mjs`: 17 of 17. The real built issuer, origin and client containers answer STATUS fenced with their own incarnation; the issuer completes key, prepare, sealed provisioning, ready and enable under the hardened settings; a client container fetches the live issuer directory through the CONNECT proxy over TLS 1.3 with the lab CA and hostname validated; after FENCE the issuer stops serving.

## New role: private origin

`src/services/lab/src/origin/control.ts` and the `origin.mjs` bundle. Three independent counters: `protected_requests_received` is incremented for every fully parsed request to the protected route before the `X-TokenForge-Run` check, `generation_mismatches` for a wrong, missing or duplicated header, `resources_served` only when served. Malformed requests that never parse and other paths are not counted. REPORT says counts are unavailable while a handler is still running rather than guessing. No process listens until ENABLE; FENCE closes the listener and keeps final counts.

## Limits and open items

- **The gateway now runs in this Compose file.** Its container starts idle and fenced; the controller launches `node /app/dist/serve.mjs` inside it with `docker exec -i` and delivers its private startup input on stdin (`docs/implementation/GATEWAY_RUNTIME.md`). `check-network.mjs` still swaps the issuer, gateway and origin commands for inert listeners, so it proves network paths only; the deployed suite (`docs/demo/DEMO.md`) proves behavior.
- Redis ACLs, policy, clock and script loading are done by the controller through the shared artifact (`docs/implementation/REDIS_BOOTSTRAP.md`); this file creates only the controller account. Redis runs in a 384 MiB container with `maxmemory 268435456`, `noeviction`, no persistence and no replica; the network check verifies those live settings and the container memory limit.
- Docker Desktop on Windows was the only runtime tested. The checks read `/proc` inside Linux containers, but a native Linux host has not been tried.
- `apk add` in the proxy image needs network access at build time; the package version is pinned, the Alpine package index is not.
- Tinyproxy has no option to disable plain-HTTP proxying; the anchored `host:443` filter is what refuses it. A tinyproxy upgrade should rerun the checks.
- Compose builds the lab image once per lab service (seven times, cached after the first). Harmless but noisy.
