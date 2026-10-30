# Gateway runtime and controller integration

The gateway now has a Linux serving entry point, private control helper and one/two-worker supervisor. These are tested with real HTTPS, blind-issued tokens, restricted-ACL Redis and an independently counted origin. Compose network isolation, the deployed issuer/client/controller and the complete cross-role reset remain integration work. Contract `TF-PS024-1.0.0` is unchanged.

## Launch and private configuration

Build from the repository root using `src/services/gateway/Dockerfile`. The image's default command remains the metadata smoke check. A serving deployment explicitly runs `node /app/dist/serve.mjs`; the local package command is `npm start`. Node 24 on Linux is required. No restart or same-run worker replacement is allowed.

The controller supplies one UTF-8 JSON object over private startup stdin, then closes that stream. Input is capped at 131072 bytes and must finish within five seconds. The exact shape is:

```json
{
  "listen_host": "<gateway's concrete frontend interface IP>",
  "redis": { "username": "gateway", "password": "<private ACL password>" },
  "tls": { "key": "<private TLS key PEM>", "cert": "<TLS certificate PEM>" }
}
```

Do not put this object in shell arguments, environment, logs or Git. The gateway retains configuration in private process memory and transfers it only over its child-process IPC channels. It uses the manifest's fixed `redis:6379` and `protected-origin:8080` endpoints. Only the concrete frontend interface is selectable; unspecified addresses are refused. HTTPS port is fixed at 443. Certificates and credentials must be generated/provisioned privately before launch. Startup rejects Node preloads/inspection arguments, `NODE_OPTIONS`, `DEBUG` and `NODE_V8_COVERAGE`; deployment must also exclude external tracing/APM instrumentation.

Run as application UID 1000 with a read-only root filesystem and no Docker socket. Provide an application-owned tmpfs at `/run/ps024`, mode 0700, UID/GID 1000, size 1 MiB, `noexec,nosuid`. The control socket is created with umask 077 and mode 0600. A pre-existing socket is never unlinked at startup. Provision the directory and non-root low-port binding in Compose; the tested container runtime permits unprivileged binding to 443. Keep all roles/networks and health exposure consistent with the technical design. This component test does not prove those deployment boundaries.

## Controller sequence

Run `node /app/dist/control-helper.mjs` **inside the gateway container**, with a persistent private stdin/stdout connection (for example, controller-managed `docker exec -i`). Do not publish the Unix socket or mount it into other roles. Keep the owning helper alive throughout the run. The helper validates requests and replies, forwards only bounded schema-valid frames and never echoes submitted payloads.

1. `STATUS` with null run/config/target discovers the fresh supervisor incarnation in FENCED state.
2. Initialize Redis policy, clock, exact Lua scripts and ACLs while every role is fenced, using the accepted public manifest.
3. Send `PREPARE_RUN` with envelope `config_digest:null`, matching target incarnation/run and payload `{manifest, proposed_config_digest, role:"gateway", role_config:{}}`. This entry point obtains credentials from startup stdin; nonempty secret-path role configuration is rejected rather than silently ignored.
4. Wait for PREPARED, then `CHECK_READY`. READY requires the profile's exact worker count, imported public keys, prepared HTTPS contexts, validated Redis state/scripts/pools and fixed-origin pools. No protected listener exists yet.
5. Enable the other roles, then send gateway `ENABLE`. The supervisor timestamps one initial three-second grant, installs worker-specific copies of its **original expiry** in every worker and waits for every application acknowledgement. Only afterward does it issue LISTEN. Each worker checks the lease before and after listening. ENABLED is returned only after all listener acknowledgements while that original lease remains active. This is a barrier before activation, not simultaneous listener activation.
6. Send `HEARTBEAT {seq}` every second, with increasing sequences and at most one outstanding heartbeat. Every renewal checks the existing lease before forwarding the original supervisor timestamp/expiry to workers. Repeated ENABLE and duplicate/out-of-order heartbeats do not extend a lease. Missing/late acknowledgements close the run.
7. Use `REPORT` for aggregate verification-attempt counts by public worker index. Measurements remain empty, shared-source evidence is unknown and origin evidence unavailable here; the controller must obtain real origin counts separately. No token identifiers, client addresses or individual event histories are reported.
8. `FENCE {reason}` may deliberately use stale/null run/config/target to stop the current service. Wait for its strong acknowledgement before external teardown. STATUS/FENCE remain available after closure; the closed run identity/latch is retained. This process never prepares another run, even after FENCE. Recreate roles only after the complete reset barrier and use a fresh key/run.

The helper owning the first accepted PREPARE link is the supervision owner. Losing it closes all workers; closing an unrelated discovery/STATUS connection does not. Control input uses newline-delimited strict UTF-8 JSON with a 65536-byte frame cap, four connections, at most eight ordinary pending requests per connection and one reserved FENCE path. Duplicate outstanding IDs, malformed frames or output-budget violations close that link. Conflicting mutations are refused while another mutation is pending; STATUS/FENCE remain responsive. The controller must correlate replies by request ID rather than arrival order.

## Worker supervision and stop guarantees

The primary uses explicit `cluster.SCHED_NONE` with a shared listening handle. The default round-robin scheduler has a primary-process accepted-socket queue outside worker caps; it is deliberately avoided. Worker scheduling can be uneven, so cross-worker tests and benchmarks must measure actual verification attempts rather than assume equal distribution. All processes use a common same-container OS monotonic clock; startup brackets each child's timestamp between parent reads.

Workers independently enforce their leases before admission and protected I/O. A paused supervisor cannot grant them fresh local durations. Worker fault/exit, private IPC loss, owning helper loss, unsafe Redis state or controller-lease expiry closes every sibling without respawn. Parent death disconnects and exits the workers. Startup and per-command application acknowledgements have fixed deadlines; a successful IPC send callback alone is never treated as readiness or execution.

Gateway FENCE latches closure before callbacks, stops/aborts each worker and waits for confirmed process exits. A worker that does not stop within one second is sent SIGKILL; acknowledgement still waits for exit, not a timer or IPC disconnect. Cleanup failures are contained per worker so siblings are still stopped. The primary retains its control socket for status. If exits cannot be confirmed, no successful FENCED reply is returned; the controller's ten-second local wait must escalate to kill-and-confirm of the container.

This proves the **gateway-local** barrier. It does not undo bytes already received by the protected origin or authorize deleting Redis state. The controller must also stop/settle or kill-and-confirm the old issuer, origin and clients before discarding replay state and provisioning a fresh run. That cross-role barrier remains the next implementation stage.

## Evidence and limits

Supervisor unit tests cover all-worker activation, delayed acknowledgements, lease expiry before late renewal, original grant timestamps, one outstanding heartbeat, FENCE races, late worker factories, sibling faults and exception-safe exit barriers. Isolated Linux tests exercise both B0 and B1 through the production entry point and real shared port, one successful concurrent redemption/one origin arrival, verification attempts on every configured worker, helper loss, supervisor pause, stopped-worker forced termination, abrupt parent death, malformed control and the actual helper's reserved FENCE path. Temporary test TLS material travels over private stdin and never enters the runtime image.

The isolated test namespace has loopback aliases for the fixed Redis/origin names and a private control tmpfs. It has no host-published ports, external network or Docker socket. This proves process/control compatibility, not Compose isolation, realistic throughput or end-to-end issuer/client HTTP enrollment. Those require the subsequent lab integration and performance stages.

Runtime behavior references: [Node cluster scheduling](https://github.com/nodejs/node/blob/v24.22.1/doc/api/cluster.md) and [child-process IPC](https://github.com/nodejs/node/blob/v24.22.1/doc/api/child_process.md).
