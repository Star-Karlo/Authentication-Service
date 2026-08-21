# Testing

Two suites: **unit tests** that need nothing, and **integration tests** that run
against real databases. This document says what each covers and **why that
particular thing is worth a test** — most exist because the monolith got the
same thing wrong, and two exist because they caught a live bug in this code.

```bash
make test                     # unit tests, every module
make test-integration-up      # throwaway Postgres + MongoDB on non-default ports
make test-integration         # integration tests, every service
make test-integration-down    # remove the containers
make test-cover               # unit tests with coverage (see the note at the end)
```

---

## The two bugs integration tests found

Both were invisible to unit tests, and both would have shown up in production.

**1. A GORM column-name mismatch stopped every user insert.** GORM derives a
column name from the Go field name, and `AcceptedTnCAt` becomes
`accepted_tn_c_at` — the capital C starts a new word — while the migration
declares `accepted_tnc_at`. Every insert into `users` failed with
*column does not exist*. Neither the model nor the SQL was wrong on its own; only
the pair was. Fixed with an explicit column tag, and
`TestModelColumnsMatchTheSchema` now compares **every** model against
`information_schema` in both Postgres services so the class cannot recur.

**2. Mongo index creation failed, so neither Mongo service could start.** Index
keys must be an *ordered* document. The original code used
`map[string]interface{}`, and a Go map has no defined order, so the driver
rejected every compound index with *"multi-key map passed in for ordered
parameter keys"*. `EnsureIndexes` returned that error, `main` propagated it, and
the process exited. Fixed by using `bson.D` throughout; a regression test now
runs `EnsureIndexes` against a real MongoDB.

Neither could have been caught without a database. That is the case for the
integration suite existing at all.

---

## Approach

**Router tests over handler mocks.** Each service builds its real `gin` engine
with nil handlers and asserts on routing and middleware. That covers the wiring
that actually breaks — a route registered outside the protected group, a missing
permission check, CORS drifting open — without standing up Postgres or MongoDB.
It runs in under a second and needs no fixtures.

**No mock-heavy service tests.** Mocking a repository to assert a repository
call was made tests the mock. The rules worth pinning — state machines, tax
arithmetic, token verification, template rendering — are pure functions and are
tested directly.

**Integration tests are build-tagged and skip themselves.** They carry
`//go:build integration`, so `make test` never compiles them, and each skips
rather than fails when its `*_TEST_DSN` / `MONGO_TEST_URI` variable is unset.
That keeps `go test ./...` green on a machine with no databases while CI, which
sets the variables, still runs them.

---

## shared — 34 tests

### `authctx/authctx_test.go` (13)
The security core. Every other service trusts this code to decide who a caller
is.

| Test | Guards against |
|---|---|
| `TestSignAndVerifyRoundTrip` | Principal, role, company and permission map surviving a sign/verify cycle |
| `TestVerifierRejectsForeignKey` | The core split guarantee: only the auth service can mint a token |
| **`TestVerifierRejectsAlgNone`** | The monolith's keyfunc returned the secret without checking the declared algorithm. An attacker strips the signature, sets `alg: none`, and is admitted as anyone. |
| **`TestVerifierRejectsHMACSignedWithPublicKey`** | The other half of `alg` confusion: sign with HS256 using the *public* key as the shared secret |
| `TestVerifierRejectsExpiredToken` | Expiry actually enforced |
| `TestVerifierRequiresExpiry` | A token with no `exp` never expires, turning one leak into permanent access |
| `TestVerifierRejectsForeignIssuer` | A token from another system sharing the key |
| `TestVerifierRejectsMalformedInput` | Includes a literal 32-character string — the monolith admitted any such string as a valid static token |
| `TestHasModule` | Root accounts unrestricted; a sub-account with no map can do **nothing**, not everything |
| `TestHasRole`, `TestPrincipalContextRoundTrip`, `TestOutgoingTokenPropagation`, `TestNewVerifierRejectsBadKeyMaterial` | Role matching, context plumbing, empty-token propagation |

### `query/query_test.go` (9)
The filter/sort allowlist is a **security boundary**, not a convenience.

- `TestParseRejectsFieldsOutsideTheAllowlist` — a client cannot filter or sort by `password_hash`.
- `TestParseRejectsInjectionAttempts` — `order_number; DROP TABLE orders`, `1=1`, `(SELECT …)`, `$where`, `__proto__`.
- `TestPageSizeIsClamped` — without a ceiling, `?pageSize=1000000` is a denial of service dressed as a normal request.
- `TestMalformedJSONIsIgnored` — legacy clients send these from stored bookmarks; a stale filter must not fail the whole request.
- `TestFieldSetResolve` — **a nil FieldSet denies everything.** A repository that forgets to declare its allowlist should lose functionality, not gain an open query surface.

### `logger/logger_test.go` (8)
- `TestFanoutReachesEverySink` — if Fluentd is down, stdout must still receive the line. Also catches the subtle bug where handlers consume the record's attribute iterator, so later sinks arrive empty.
- `TestInitWithUnreachableFluentdStillLogs` — the degradation guarantee: a service starts and logs even when the collector is unreachable.
- `TestAddAttrFlattening` — groups become dotted keys, which index far better than nested objects.

### `safeconv/safeconv_test.go` (4)
Go's integer conversions wrap silently: `int32(MaxInt32 + 1)` is negative. These
clamp instead, so a bad page count cannot surface to a client as a negative
number of pages, and a generator fault cannot put a non-digit inside an OTP.

---

## authentication-service — 16 tests

### `tests/unit/routes_test.go` (8)
| Test | Guards against |
|---|---|
| `TestProtectedRoutesRejectAnonymousRequests` | Walks all 12 authenticated routes. The monolith's shape: a route registered outside the protected group, or a handler reading the token context without checking it first — which panicked. |
| `TestGarbageTokensAreRejected` | Empty bearer, two-segment JWT, `alg: none`, bare string, and a 32-character string |
| **`TestSwaggerHiddenInProduction`** | The OpenAPI document describes every endpoint and shape — precisely the reconnaissance an attacker would otherwise guess at |
| `TestCORSRejectsUnlistedOrigins` | `cors.Default()` allowed **every** origin on a credentialed API |
| `TestRequestIDIsAssigned` | Correlation across four services; a caller-supplied id is preserved, not replaced |
| `TestPublicRoutesAreReachable`, `TestHealthEndpoint`, `TestSwaggerServedOutsideProduction` | The public surface is exactly login/register/refresh/availability |

### `tests/unit/auth_test.go` (4)
Password strength including the **72-byte bcrypt limit** — beyond it bcrypt
silently truncates, so a longer password gives a false sense of strength.
Permission evaluation, root-account bypass, constant-time comparison.

### `tests/unit/models_test.go` (4)
Postgres `text[]` round-tripping with quotes, commas and backslashes; session
and API-key validity including *revoked but not yet expired*.

---

## masterdata-service — 12 tests

### `internal/config/guard_test.go` (4)
**The regression test for the accident this whole guard exists to prevent.**

- Refuses the legacy Atlas cluster, `prod`, `test`, `local`, a legacy name in the URI path, an empty name, and a case variant (`PROD`).
- Accepts fresh targets.
- `TestCollectionPrefixAvoidsLegacyNames` — the second line of defence: `md_` means even a target that slipped past the first check cannot overwrite `trucks` or `warehouses`.

### `tests/unit/models_test.go` (4)
- **`TestGeoPointOrdering`** — GeoJSON stores `[longitude, latitude]`, the reverse of how people say it. This pins the transposition that would otherwise silently put every warehouse in the wrong hemisphere.
- Accessors on malformed documents must not panic.
- `TestIsValidKind` — the kind selects *which data is read*, so an unknown one must be rejected before it reaches a query.

### `tests/unit/routes_test.go` (4)
Master data has **no public surface at all**: catalogue contents and a company's
fleet are both commercially sensitive. All 16 routes must 401 anonymously.

---

## business-service — 13 tests

### `tests/unit/status_test.go` (6)
The heart of the service.

- `TestOrderTransitionsAllowed` — the moves the business needs, including the admin escape hatch so a stuck order never needs a database edit.
- **`TestOrderTransitionsRefused`** — the moves the monolith *allowed* because every status change went through one generic handler: a driver approving an order, a shipper assigning a driver, draft → completed, reopening a completed or cancelled order.
- `TestShipmentLifecycleInOrder` — walks all 11 steps, each reachable only from the one before.
- **`TestShipmentRoleSeparation`** — a driver cannot approve their own loading or sign off their own delivery. The monolith aliased `ttd-loading`, `checklist-loading` and `start-loading` onto one handler, losing the distinction.
- **`TestStatusLabelsAreDomainScoped`** — the regression test for a collision found while building: `draft`, `submitted`, `assigned` and `cancelled` each exist on more than one entity and do not mean the same thing.
- `TestNextStatesReflectRole` — a client renders only buttons that will work.

### `tests/unit/invoice_test.go` (3)
- **`TestInvoiceRecalculate`** — PPN is *added*, PPH23 is *withheld*. Reversing either sign changes what the customer owes, so both directions are asserted explicitly. Includes a case (`0.30 × 0.10`) that binary floating point cannot represent, which is why amounts are `decimal.Decimal`.
- `TestInvoiceRecalculateIsIdempotent` — tax is a function of the subtotal, not of the running total.
- `TestAgreementIsUsable` — validity **inclusive at both ends**, strict verification, non-active statuses.

### `tests/unit/routes_test.go` (4)
All 23 business routes must 401 anonymously. This service holds every company's
prices, volumes and counterparties; the monolith's unauthenticated
`/order/detail` and `/track-order/:id` exposed order contents to anyone who
could guess a number.

---

## notification-service — 18 tests

### `tests/unit/templates_test.go` (5)
- `TestRenderProducesCompleteCopy` — both languages, multi-parameter templates, fallback for unknown and regional tags.
- **`TestRenderRejectsMissingParams`** — sending "Order  is awaiting your approval" is worse than sending nothing: the recipient cannot act on it and cannot tell what went wrong.
- **`TestEveryContractEventHasATemplate`** — keeps the proto and the registry in step. **This test found a real gap while being written:** `ORDER_REQUEST_DELIVERY` was declared in the contract with no copy, which would have failed at delivery time in production.
- `TestRenderedNumbersAreReadable` — JSON numbers decode as `float64`; an amount must not render as `9100000.000000`.

### `tests/unit/routes_test.go` (7)
- **`TestHealthReportsChannelAvailability`** — a silently unconfigured channel looks identical to a broken one. Health reports push/email/whatsapp so the difference is visible without reading the environment.
- `TestWebhookVerification` — correct token echoes the challenge; wrong, missing and wrong-mode are all 403 and must not echo it.
- **`TestWebhookAcknowledgesUnparseableBody`** — Meta redelivers on any non-2xx, and an unparseable body will not become parseable on retry.
- **`TestInboxIgnoresUserIdParameter`** — supplying someone else's id as a query parameter must not work; the id comes from the token.
- `TestOTPRoutesArePublic` — reached before a user has a token, by necessity; abuse is bounded by cooldown and attempt cap instead.

### `tests/unit/phone_test.go` (3)
Indonesians write numbers as `08123…`, `+628123…`, `628123…`, with dashes,
spaces and brackets. The legacy service passed whatever it was given straight to
the WhatsApp API, so **whether a code arrived depended on how the user happened
to type their number.** Also asserts idempotency, since normalised numbers are
stored and reused.

### `tests/unit/webhook_test.go` (3)
The Cloud API envelope (`entry[].changes[].value.messages[]`) where every level
is optional, and the *status callback* shape that arrives on the same endpoint
carrying `statuses` rather than `messages` and must not be mistaken for inbound
mail.

---

## Coverage tooling note

`make test-cover` needs the `covdata` tool. The toolchain module Go downloads
automatically when a dependency requires a newer Go than the local install is
**trimmed and does not ship it** — `gin` and `grpc` both require Go 1.25, so a
machine on 1.24 hits this.

```
go: no such tool "covdata"
```

Fix by installing a full Go 1.25+ (`brew upgrade go`). Plain `make test` works
either way, which is why coverage is a separate opt-in target rather than part
of the default.

---

## Integration tests — 29 tests

Run against a real Postgres 16 and MongoDB 7. `make test-integration-up` starts
both on non-default ports (55432, 57017) so they cannot collide with a database
you already run.

### authentication-service (9)

| Test | Covers |
|---|---|
| **`TestModelColumnsMatchTheSchema`** | Every model's columns against `information_schema`. Found the `accepted_tn_c_at` bug. |
| **`TestPartialUniqueIndexAllowsReuseAfterSoftDelete`** | Why the migration uses a partial index: a soft-deleted user must not hold their email forever, but a live duplicate must still be refused. |
| `TestFindByIdentifierMatchesAllThreeColumns` | The single-query login lookup across email, username and phone, including CITEXT case-insensitivity |
| `TestRevokeAllEndsEverySession` | What makes a password change meaningful. Also asserts another user's sessions are untouched, and that revocation is a timestamp so the audit trail survives. |
| `TestSingleDeviceEvictionKeepsTheNewestSession` | The legacy `tokenKapps` rule |
| `TestExpiredSessionsArePruned` | The sweep, including its 7-day grace period |
| `TestRefreshTokenLookupUsesTheHash` | The plaintext refresh token is never stored |
| `TestCompanyMemberListingIsScoped` | One company cannot enumerate another's staff |
| `TestUpdateFieldsRejectsUnknownRows` | A partial update on a missing row reports it rather than silently succeeding |

### business-service (11)

| Test | Covers |
|---|---|
| **`TestNumberSequenceIsCollisionFreeUnderConcurrency`** | 200 concurrent callers must get 200 distinct numbers **with no gaps**. The legacy read-then-write could hand the same order number to two requests. |
| **`TestConcurrentTransitionsProduceExactlyOneWinner`** | 20 goroutines approve the same order; exactly one succeeds, 19 get `ErrConflict`, and history holds exactly **one** approval row. This is the compare-and-set claim, tested rather than asserted. |
| `TestTransitionWritesStatusAndHistoryAtomically` | The status write and the audit row are one transaction |
| `TestTransitionFromWrongStateIsRefused` | A caller acting on a stale view leaves no trace |
| `TestApplyStatusSetsAccompanyingFields` | Assign-driver: status and driver land together, so there is no "assigned" order with no driver |
| **`TestOrderReadsAreScopedToTheCompany`** | Tenancy in real SQL. Returns `ErrNotFound`, not a permission error — a distinct response would confirm the id exists. |
| `TestFilterAllowlistIsEnforcedInSQL` | The allowlist survives to the database; nothing downstream reintroduces a dropped field |
| **`TestSortByEveryAllowlistedFieldExecutes`** | Sorts by all 11 allowlisted fields. Catches a typo between a `FieldSet`'s mapped column and the actual schema, which is otherwise invisible until someone sorts by it in production. |
| `TestInvoiceDoubleBillingIsDetected` | An order cannot be billed twice; a cancelled invoice releases its orders |
| `TestModelColumnsMatchTheSchema` | All 9 business models against the live schema |
| `TestNumberSequenceScopesAreIndependent` | Orders, invoices and agreements each get their own counter; a new year restarts |

### masterdata-service (7)

| Test | Covers |
|---|---|
| **`TestEnsureIndexesCreatesWhatTheQueriesNeed`** | The unique `(kind, code)`, unique `(companyId, policeNumber)` and geospatial indexes genuinely exist. A missing index is invisible in a test dataset and crippling in a real one. |
| `TestCatalogUpsertIsIdempotent` | What makes the seed loader safe to re-run: a second upsert updates in place and keeps the id, so references do not break |
| `TestCatalogLookupIsScopedToItsKind` | An id from one catalogue must not resolve under another |
| `TestTruckReadsAreScopedToTheCompany` | Tenancy, plus the deliberate cross-service read that skips the filter |
| `TestPoliceNumberIsUniquePerCompany` | Two companies may register the same plate (a vehicle changes hands); one company may not list it twice |
| `TestDriverPairingIsIdempotent` | `$addToSet`, and the lookup the business service uses before allowing an assignment |
| **`TestWarehouseProximityQuery`** | The 2dsphere index with three real Indonesian locations: a 1 km radius finds one depot, 15 km finds two nearest-first, and Surabaya 700 km away never matches |
| `TestWarehouseCoordinatesRoundTrip` | GeoJSON ordering across a real write and read. Transposing latitude and longitude puts every Indonesian warehouse in Somalia, and nothing in the code would complain. |

### notification-service (2)

| Test | Covers |
|---|---|
| **`TestEnsureIndexesSucceedsAgainstRealMongo`** | The regression test for the bug that stopped the service starting. Also asserts idempotency, since it runs on every boot. |
| `TestNotificationIndexesSupportTheQueriesWeRun` | The sparse-unique idempotency key (retries deliver twice without it), the inbox index, and the TTL indexes that stop OTPs and webhook payloads growing without bound |

---

## Coverage tooling note

`make test-cover` needs the `covdata` tool. The toolchain module Go downloads
automatically when a dependency requires a newer Go than the local install is
**trimmed and does not ship it** — `gin` and `grpc` both require Go 1.25, so a
machine on 1.24 hits this.

```
go: no such tool "covdata"
```

Fix by installing a full Go 1.25+ (`brew upgrade go`). Plain `make test` works
either way, which is why coverage is a separate opt-in target rather than part
of the default.

---

## Gaps worth closing

1. **gRPC contract tests** — the mapping layers between domain models and protobuf are currently only exercised through compilation.
2. **Delivery tests** for the notification dispatcher with stub `Sender`s, covering per-recipient language, the actor exclusion, and the worker-pool bound.
3. **An end-to-end test** across all four services, driving the order lifecycle over HTTP against a running stack.
4. **Load testing** the order listing, to confirm the indexes chosen are the ones the planner actually uses.
