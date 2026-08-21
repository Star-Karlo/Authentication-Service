# Logging, API Documentation and Linting

The three cross-cutting concerns, and how each is wired.

---

## 1. Logging

### Two sinks, one of which never fails

Every service writes **JSON to stdout always**, and additionally forwards to
**Fluentd** when `FLUENTD_HOST` is set.

Stdout is never disabled. A service whose only log sink is an unreachable
collector is a service with no logs at all — which is the failure mode the
legacy `logger.Init(host, port)` had, since it swallowed connection errors and
then logged nothing.

```
              ┌──────────────┐
  slog ──────▶│ fanoutHandler│───▶ stdout (JSON)          always
              └──────────────┘───▶ Fluentd (msgpack)      when configured
```

Implementation: [`shared/logger`](../../internal/platform/logger/logger.go).

### Behaviour under failure

| Situation | What happens |
|---|---|
| `FLUENTD_HOST` unset | stdout only. Correct for local dev and for platforms that collect stdout. |
| Fluentd unreachable at startup | A warning to stdout, then stdout-only. **The service still starts.** |
| Fluentd dies mid-run | Records queue up to `FLUENTD_BUFFER_LIMIT`, then drop. stdout is unaffected. |
| Fluentd slow | `FLUENTD_ASYNC=true` means a log call never blocks a request handler. |

Dropping logs is survivable; stalling every handler on a log write is not.

### Configuration

```bash
LOG_LEVEL=info                  # debug | info | warn | error
FLUENTD_HOST=fluentd            # unset disables forwarding
FLUENTD_PORT=24224
FLUENTD_TAG_PREFIX=karlo        # tags become karlo.business, karlo.auth, …
FLUENTD_ASYNC=true              # never block a request on a log write
FLUENTD_BUFFER_LIMIT=8388608    # bound memory during an outage
FLUENTD_TIMEOUT=3s
```

### Record shape

```json
{
  "time": "2026-08-21T09:14:03.221Z",
  "level": "INFO",
  "msg": "request",
  "service": "business",
  "env": "production",
  "request_id": "8f14e45f-ea2b-4c1e-9f1a-2c9d3a4b5c6d",
  "method": "PUT",
  "path": "/api/v1/orders/.../status",
  "status": 409,
  "duration_ms": 12,
  "ip": "10.0.3.44",
  "user_id": "…",
  "role": "transporter"
}
```

`service` and `env` are attached to every line, so lines from four processes and
two environments stay distinguishable in one index. Attribute groups are
flattened to dotted keys (`http.status`) because most backends index flat keys
far better than nested objects.

### Request correlation

[`RequestLogger`](../../internal/middleware/request_logger.go)
assigns an `X-Request-Id`, **preserving one the caller supplied** so a trace
started at the gateway survives across all four services. It is echoed in the
response header.

The same middleware puts the end user's token on the outgoing context, so gRPC
calls made while serving a request carry the same principal downstream.

### What is deliberately not logged

**Request bodies.** The authentication service handles passwords on nearly every
endpoint, and a body-logging middleware is the most common way credentials reach
a log aggregator. Response bodies are likewise not logged: order and invoice
contents are commercial data.

### Local collector

`docker compose up` starts Fluentd with
[`fluentd/fluent.conf`](../fluentd/fluent.conf): records go to the container's
stdout (`docker compose logs fluentd`) and to hourly files in a bounded buffer.

For production, replace the file store with your destination — CloudWatch Logs,
OpenSearch, Datadog. **Nothing in the services changes**: they only know how to
forward.

---

## 2. API documentation (Swagger / OpenAPI)

### Where it lives

Each service generates its own document from annotations on the handlers:

| Service | UI | Raw document |
|---|---|---|
| authentication | http://localhost:5001/swagger/index.html | `/swagger/doc.json` |
| masterdata | http://localhost:5002/swagger/index.html | `/swagger/doc.json` |
| business | http://localhost:5003/swagger/index.html | `/swagger/doc.json` |
| notification | http://localhost:5004/swagger/index.html | `/swagger/doc.json` |

Committed artefacts live in each service's `docs/` (`swagger.json`,
`swagger.yaml`, `docs.go`).

### Hidden in production

```go
if !d.Config.IsProduction() {
    router.GET("/swagger/*any", ginswagger.WrapHandler(swaggerfiles.Handler))
}
```

The document describes every endpoint, its parameters and its response shapes —
exactly the reconnaissance an attacker would otherwise have to guess at. A test
in each service asserts the route 404s in production.

### Regenerating

```bash
make swagger                                    # all services
cd business-service && make swagger             # one
```

Run this whenever a handler annotation changes. **CI should run it and fail on a
diff**, otherwise the published document drifts from the code and becomes worse
than no document.

### Authenticating in the UI

Every protected endpoint is marked `@Security BearerAuth`. Get a token from
`POST /api/v1/auth/login` on the authentication service, then paste
`Bearer <token>` into the **Authorize** dialog.

### Version pinning

The `swag` CLI and the `swaggo/swag` library must match — a mismatch produces
`unknown field LeftDelim in struct literal`. Both are pinned to **v1.16.4**;
`make tools` installs the right CLI.

---

## 3. Linting

### Configuration

One [`.golangci.yml`](../../internal/platform/.golangci.yml) shared verbatim by all five
modules, in golangci-lint **v2** format.

```bash
make lint                                       # all modules
cd business-service && golangci-lint run ./...  # one
```

All five modules currently report **0 issues**.

### Enabled linters and what each has caught here

| Linter | Catches | Found in this codebase |
|---|---|---|
| `govet` | Suspicious constructs | **A protobuf message copied by value** in the auth gRPC server — which copies an internal mutex and is a data race |
| `gosec` | Security issues | Silent integer overflow in several proto conversions |
| `errcheck` | Dropped errors | 8 unchecked `Close` calls on cursors and response bodies |
| `staticcheck` | Bugs and deprecations | The deprecated `google.CredentialsFromJSON`, which accepts unvalidated credential configurations |
| `bodyclose`, `rowserrcheck`, `sqlclosecheck` | Leaked HTTP bodies, DB rows, statements | — |
| `noctx` | Requests without a context | `net.Listen` in the gRPC server, now using `ListenConfig` |
| `unparam`, `unconvert`, `ineffassign`, `unused` | Dead weight | Two helpers taking a parameter that never varied |
| `misspell`, `revive` | Typos and style | — |

### Notable fixes the linter drove

**Integer overflow.** `int32(v)` wraps silently, so a value past the ceiling
becomes negative. Now routed through [`shared/safeconv`](../../internal/platform/safeconv/safeconv.go),
which clamps — a saturated page count is correct enough; a negative one is a
client-visible bug.

**Deprecated OAuth path.** `google.CredentialsFromJSON` is deprecated because it
accepts any credential configuration without validating it, including
external-account configurations that can point at an attacker-controlled token
URL. Replaced with `JWTConfigFromJSON`, which accepts only a service-account key
— which is what FCM needs anyway.

### Suppressions

Every `#nosec` and `//nolint` in the tree carries a written reason. There are
four, all of the same kind: reading a file whose path comes from this process's
own configuration (`JWT_*_KEY_FILE`, `FCM_CREDENTIALS_FILE`, the seeder's
`-file` flag) rather than from a request. The key-file reads are consolidated
into one `readKeyFile` helper so the justification is written once.

Test files exclude three linters, for reasons stated in the config: fixtures
deliberately contain credential-shaped strings (`gosec`), helpers take
parameters that vary across a suite even when one test passes a single value
(`unparam`), and a test building an *inbound* request has no context to
propagate (`noctx`).

### Installing

```bash
make tools    # buf, protoc plugins, swag v1.16.4, golangci-lint
```

golangci-lint v2 requires Go 1.26+ to build. It runs fine against modules
targeting older versions.

---

## Suggested CI

```yaml
- make tools
- make build
- make test
- make lint
- make swagger && git diff --exit-code   # fail if the document drifted
- cd proto && buf lint && buf breaking --against '.git#branch=main'
```

The last line is worth having: `buf breaking` catches a contract change that
would break a service still running the old bindings, which is the failure mode
a four-service split introduces and a monolith does not have.
