# Regional portal layout preview

The regional product layout is available on loopback with Node 24.

```sh
node src/services/portal/src/serve.mjs
```

Open `http://127.0.0.1:4174/`. The page labels its preview status. Client/profile choices and acquire/access controls remain disabled while live integration awaits accepted K01 public envelopes, K02/K03 enforcement and K04 evidence. Its empty evidence fields preserve the distinction between an unobserved run and a measured zero count.

The research brief itself is served by the existing private origin at `/resource`. The preview presents the resource title and access state. The gateway remains responsible for access enforcement.

The preview server serves two fixed assets over GET/HEAD, validates Host/Origin, and uses a local-only content policy. Future live actions need their agreed fixed command schemas, CSRF protection and supervised controller dispatch. The existing report viewer retains its read-only interface.

Focused preview checks:

```sh
node --test src/services/portal/test/serve.test.mjs
```

No external assets or runtime UI dependencies are required. The package has its own manifest and lockfile.
