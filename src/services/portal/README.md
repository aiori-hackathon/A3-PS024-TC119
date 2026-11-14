# Research access portal

The local portal controls supervised laboratory runs through an injected backend. The browser receives sanitized status, aggregate origin evidence and authorized resource text. Credential acquisition and redemption remain inside the laboratory client processes.

## Start

The standalone entry point serves the read-only layout preview with disabled controls.

```sh
node src/services/portal/src/serve.mjs
```

Open `http://127.0.0.1:4174/`. Live integration imports the same server.

```js
import { startPortal } from './src/services/portal/src/serve.mjs';
const { server, port } = await startPortal({ port: 4174, backend });
```

`startPreview(port)` remains available. `port: 0` selects an available loopback port. The server binds to `127.0.0.1`.

## Backend contract

The integrator supplies `backend.status()` and `backend.execute(command)`, both asynchronous. **The backend must return its reviewed, secret-free public projection.** It must enforce run revision, immutable active profile, authorization, supervision and fail-closed recovery. This package supplies the HTTP boundary and presentation.

Status fields are shown below. Unknown observations use `null` or omitted fields. A measured zero requires an observed snapshot.

```js
{
  observedAt: '2026-11-14T00:00:00.000Z',
  state: 'idle', // idle, starting, active, resetting, uncertain, error
  profile: null, // ip, type2-bearer, arc, type2-holder
  revision: 0, // run-generation counter, stable during acquire/access
  window: { label: 'Server-confirmed accepted window' },
  clients: [{ clientId: 'A', estimatedUsesLeft: null, state: 'Awaiting run' }],
  evidence: {
    observedAt: '2026-11-14T00:00:00.000Z',
    state: 'verified', // verified, incomplete, mismatch
    requestsReceived: 0,
    resourcesServed: 0,
    generationMismatches: 0
  },
  comparison: [{
    profile: 'ip', state: 'observed', accepted: null, denied: null,
    honestDelivered: null, originArrivals: null, issuanceBytes: null,
    issuanceInteractions: null, latencyMs: null
  }],
  theftScene: {
    state: 'observed', bearerOutcome: 'Sanitized observed result',
    holderOutcome: 'Sanitized observed result',
    attackOriginArrivals: null, ownerOriginArrivals: null
  }
}
```

Exact command shapes are enforced. Clients are `A` through `E`. Revisions are nonnegative safe integers.

```js
{ action: 'start_run', profile: 'arc' }
{ action: 'reset_run', revision: 0 }
{ action: 'acquire', clientId: 'A', revision: 1 }
{ action: 'access', clientId: 'A', revision: 1 }
{ action: 'run_comparison', revision: 1 }
{ action: 'run_theft_scene', revision: 1 }
```

Execution resolves to `{ outcome, message?, status?, authorizedAccess? }`. Common outcome labels include `started`, `reset`, `delivered`, `refused`, `uncertain`, `comparison-complete`, `theft-complete` and `unavailable`. The backend includes `authorizedAccess: { clientId, text }` only when that access actually delivered the protected resource. The portal exposes this field only for an `access` command. Browser presentation uses text nodes. Resource text clears when the run revision changes and identifies previous delivery.

## HTTP boundary

The fixed routes are `GET /api/status`, `POST /api/command` and `GET /api/operations/{opaqueId}`. Bootstrapping status establishes a bounded HttpOnly SameSite=Strict session cookie and returns its CSRF token. Mutation requires the exact same-origin `Origin`, matching session/token and `application/json`. Host and supplied Origin must exactly match a supported loopback authority. Cross-site fetches are rejected. Responses use `no-store`, a self-only script/connect/style CSP and fixed safe errors.

Commands are limited to 4096 bytes. JSON responses are limited to 262144 bytes. At most one mutation and four backend status reads are in flight. The server retains at most eight completed session-scoped operations, each for two minutes, plus the active operation. It never retries mutations. The browser keeps one latest result and aggregate evidence. Backend exception details are discarded.

## Checks

```sh
node --test src/services/portal/test/serve.test.mjs
```

Tests cover preview behavior, Host/Origin/CSRF boundaries, exact command schemas, byte limits, asynchronous single-flight operations, session-scoped result lookup, authorized resource projection, safe failure labels and bounded completed retention. No external assets or runtime UI dependencies are required.
