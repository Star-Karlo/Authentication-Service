# Karlo Authentication Service

**HTTP** `:5001` · **gRPC** `:6001` · **Store** PostgreSQL

Identity, company membership, sessions, permissions and API keys.

**This service is the authority on who a caller is.** It holds the RS256 private
key and is the only party that can mint a token; every other service holds only
the public key and verifies locally, so there is no network hop on the hot path
and no shared secret a compromised service could use to forge identities.

It depends on nothing. Every other service depends on it.

## Getting started

```bash
cp .env.example .env          # set DB_PASSWORD, SERVICE_TOKEN, ACCEPTED_SERVICE_TOKENS
make keys                     # development RSA signing pair, written to .keys/ (gitignored)
make migrate-up               # apply the schema
make run
```

Other services need the **public** key from `.keys/jwt-public.pem`; point their
`JWT_PUBLIC_KEY_FILE` at it. The private key never leaves this service.

## Notable behaviour

- **Login failures are uniform.** The same error whatever went wrong, and a dummy bcrypt comparison runs even when no user matched, so neither the message nor the timing reveals whether an account exists.
- **Refresh tokens rotate.** The old one stops working the moment a new pair is issued, so a stolen token is usable at most once.
- **A password change, a permission change or a suspension revokes sessions.** The permission map is embedded in issued tokens, so a change only takes effect once those are gone.
- **API keys replace the ten hardcoded tokens** the monolith compiled into its constants file. Stored hashed, scoped, and expirable.


## Layout

```
cmd/server/           entrypoint
internal/
  config/             environment loading; no defaults for security controls
  models/             domain types
  repository/         the only code that talks to the database
  services/           business rules
  handlers/           HTTP
  grpcserver/         gRPC contract implementation
  clients/            outbound gRPC to other services
  routes/             the HTTP surface, one handler per path
  platform/           shared plumbing, vendored (see below)
proto/                gRPC contracts
docs/                 generated OpenAPI document
tests/unit/           no I/O; run always
tests/integration/    real database; build-tagged
```

## Platform documentation

The cross-service documentation — data ownership, business flows, testing and
observability — is **not in this repository**. It describes all four services,
so it lives once in the workspace that holds them side by side, at
`../docs/`, rather than in four drifting copies.

This README covers what is specific to this service.

## About `internal/platform`

This directory is **vendored, not authored here**. It holds the plumbing every
Karlo service shares: RS256 token verification, the structured logger, the
gRPC server and client setup, the query allowlist, and the HTTP response
envelope.

Each service repo carries its own copy so it is fully standalone. The cost is
that a change to shared plumbing — a fix to token verification, say — has to be
applied to all four repos. **`internal/platform/authctx` is security-critical:
a change there must land everywhere.**

The same applies to `proto/`. The contracts are duplicated by design; when one
changes, copy the updated `.proto` into every repo that speaks it and run
`make proto` there. CI fails if the committed bindings do not match the
contracts in the repo, which catches a forgotten regeneration but not a
forgotten copy.

## Commands

| | |
|---|---|
| `make tools` | install buf, the protoc plugins, swag and golangci-lint |
| `make run` | run the service |
| `make test` | unit tests |
| `make test-integration` | integration tests (needs a database; see above) |
| `make lint` | golangci-lint |
| `make proto` | regenerate the gRPC bindings |
| `make swagger` | regenerate the OpenAPI document |
| `make docker` | build the container image |

## API documentation

`make run`, then open **http://localhost:5001/swagger/index.html**.

The browser is served only outside production: the document describes every
endpoint and response shape, which is the reconnaissance an attacker would
otherwise have to guess at. A test asserts it 404s when `ENVIRONMENT=production`.
