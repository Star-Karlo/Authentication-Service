# Karlo Authentication Service

**HTTP** `:5001` · **gRPC** `:6001` · **Store** PostgreSQL

Identity, company membership, sessions, module entitlement, permissions and API
keys.

**This service is the authority on who a caller is.** It holds the RS256 private
key and is the only party that can mint a token; every other service holds only
the public key and verifies locally, so there is no network hop on the hot path
and no shared secret a compromised service could use to forge identities.

It depends on nothing. Every other service depends on it.

## Getting started

```bash
cp .env.example .env          # set DB_PASSWORD, SERVICE_TOKEN, ACCEPTED_SERVICE_TOKENS
make keys                     # development RSA signing pair, written to .keys/ (gitignored)
make migrate-up               # 000001 init · 000002 company modules ·
                              # 000003 multi-product · 000004 shared IAM
make run
```

Other services need the **public** key from `.keys/jwt-public.pem`; point their
`JWT_PUBLIC_KEY_FILE` at it. The private key never leaves this service.

## Notable behaviour

- **Login failures are uniform.** The same error whatever went wrong, and a dummy bcrypt comparison runs even when no user matched, so neither the message nor the timing reveals whether an account exists.
- **Refresh tokens rotate.** The old one stops working the moment a new pair is issued, so a stolen token is usable at most once.
- **A password change, a permission change or a suspension revokes sessions.** The permission map is embedded in issued tokens, so a change only takes effect once those are gone.
- **API keys replace the ten hardcoded tokens** the monolith compiled into its constants file. Stored hashed, scoped, and expirable.
- **Login rate limiting is a fixed window in Redis**, keyed by a fingerprint of the identifier so no email address sits in the keyspace. With no Redis it falls back to counting audit rows rather than refusing every login.

## Access is two tiers

`company_modules` records what a **company** is entitled to;
`user_product_access` records what a **person** may do within that, per
product. Effective access is the intersection, and it is evaluated by one shared
function ([`internal/platform/authctx/claims.go`](internal/platform/authctx/claims.go))
against per-product catalogues
([`catalog_tms.go`](internal/platform/authctx/catalog_tms.go),
[`catalog_fms.go`](internal/platform/authctx/catalog_fms.go)) and a registry of
what is sellable ([`features.go`](internal/platform/authctx/features.go)).
`users.permission` is deprecated and no longer read.

The company's active modules are read at token mint time and embedded in the
token, so every service applies the first tier locally with no round trip. **If
that lookup fails the token is minted with no modules**, not all of them: the
holder authenticates but reaches nothing, and a refresh fixes it. Failing the
other way would hand out a token granting everything until it expired.

Two consequences worth knowing before reading the code:

- **A root account no longer bypasses module checks.** It is unrestricted only *within* its company's entitlement. The flag is read from `users.account_type = 'mainAccount'` rather than inferred from an absent `parent_id` — inference failed **open**, promoting any member whose parent was never recorded to unrestricted access.
- **An administrator cannot grant a module the company does not hold.** `SetPermission` refuses it, and the permission editor renders exactly the entitlement, so there is nothing to tick.

`superadmin` and `admin` are Karlo staff, not tenants, and no company's
entitlement applies to them.

## Entitlement administration, and why it is not a permission key

`/api/v1/admin/*` is the API Karlo staff use to grant and revoke a company's
modules, list what it holds, read the history and see what is sellable. It
replaces editing `company_modules` by hand, and the SQL remains documented as
the fallback for direct database work.

The group is guarded by `authctx.RequirePlatformStaff()` — the boolean
`users.is_platform_staff`, and nothing else. That is deliberate rather than
lazy. **A permission key is a thing a company can hold**, so if entitlement
administration were expressible as one, sooner or later a customer would hold
it, and the commercial boundary between what Karlo sells and what a customer
configures would not exist. `is_platform_staff` is the one property a tenant
cannot acquire. `TestOnlyStaffCanBeEntitlementAdministrators` pins it.

A grant is validated against the sellable registry and an unknown module name
is refused, because a row that gates nothing makes a company appear to hold
something it cannot reach — the mistake then arrives as a support ticket about
a feature that "was turned on" and does not work.

Revoking does **not** end sessions: entitlement travels inside the token, so a
withdrawn module keeps working for at most the life of an issued one, and the
response says so rather than leaving the caller to wonder.

## A company can now administer its own people

`PUT /users/:id`, `PUT /users/:id/suspend` and `DELETE /users/:id` used to be
guarded by `RequireRole("superadmin","admin")`. Migration `000003` had already
moved both roles onto `is_platform_staff`, so no tenant role satisfied that
guard any more: a company owner could invite a member and never remove one.
They now take `collaboration.manageMember` and `collaboration.removeMember`.

Alongside them, `GET/PUT/DELETE /users/:id/access[/:product]` decides **which
products** a member may use, as distinct from what they may do inside one. It
is bounded by the company's own entitlement — a company cannot hand its people
a product it does not hold.

## Registration is one transaction

`UserService.Register` writes the company, the user, the default entitlement
and the product-access row inside `UserRepository.Transaction`, with `WithTx`
on the four repositories involved. It was four separate writes, and a failure
part-way through left exactly the unusable state those writes exist to
prevent: a company with no entitlement, or a user with no access row — both of
which authenticate happily and then reach nothing.

The bug that prompted it is worth recording, because only a real database finds
it. `pq.StringArray(nil)` encodes as SQL `NULL`, and
`user_product_access.permissions` is `NOT NULL`. A root account is created with
no permission keys on purpose, so **every** new company registration failed at
its fourth write. `AccessRepository.permissionArray` maps nil to an empty
array; `TestRegisterCreatesAUsableCompany` asserts the column reads back
non-nil.

## Login may carry an optional product

`POST /auth/login` accepts `"product": "tms"`. It **never changes the token** —
the claims are byte-identical with and without it, and the session is already
built before the hint is looked at. All it does is turn a successful sign-in
followed by empty screens into a clear 403 at the door. On that path the
session still stands, because the credentials were right.

That invariant is the whole point: the hint arrives in the request body, so
anything that let it reach the token would mean a client could change what an
account can do by changing one field.

## One schema for both products

Migration `000004_shared_iam` makes this schema able to hold FMS as well as
TMS, so the day FMS moves is a data migration rather than a behaviour change.
It adds recorded identifier aliases (`users.fms_user_id`, `companies.slug`,
`product_roles.fms_role_id`), named permission bundles that **union** with a
user's own keys rather than replacing them, a per-company per-product
`entitlement_mode` deciding whether a missing row means denied or enabled, and
two `sessions` columns for refresh-token rotation chains.

The reasoning — particularly why the two products fail in opposite directions
and why that had to be data rather than a code branch — is in
[`../docs/DATA.md`](../docs/DATA.md) §2, and the policy in
[`../docs/PERMISSIONS.md`](../docs/PERMISSIONS.md).


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

## The integration suite refuses a database that is not a test database

`AUTH_TEST_DSN` must name a database containing `_test`, or `testDB` fails the
run before opening a connection. The suite `TRUNCATE … CASCADE`s users and
companies, and pointing it at the local development database wiped the seed
once. It is a hard failure rather than a skip, because a skip is how you end up
believing a destructive suite ran. The DSN is redacted before it reaches the
message. `make test-integration-up` creates `karlo_auth_test`.

## API documentation

`make run`, then open **http://localhost:5001/swagger/index.html**.

The browser is served only outside production: the document describes every
endpoint and response shape, which is the reconnaissance an attacker would
otherwise have to guess at. A test asserts it 404s when `ENVIRONMENT=production`.
