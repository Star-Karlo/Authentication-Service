# Data Documentation

Which store belongs to which service, what lives in it, and how records in one
service refer to records in another.

---

## 1. Ownership

Each service owns exactly one database. **No service reads another service's
store.** Cross-service data is fetched over gRPC, never by connecting to
someone else's database — that rule is what makes the boundaries real rather
than decorative.

| Service | Engine | Database | Why this engine |
|---|---|---|---|
| authentication | PostgreSQL (AWS RDS) | `karlo_auth` | Identity is relational and correctness-critical: unique email/phone constraints, foreign keys from sessions to users, and transactional permission changes all want a relational engine. |
| masterdata | MongoDB | `karlo_masterdata` | Reference data is heterogeneous and read-mostly. A rate card and a province have almost no fields in common, so a document store avoids twenty near-empty tables. |
| business | PostgreSQL (AWS RDS) | `karlo_business` | Orders, invoices and money need transactions, exact numerics and referential integrity. This is the part of the system where a lost write is a commercial dispute. |
| notification | MongoDB | `karlo_notification` | High write volume, short retention, no joins. Records are written once, read by one user, and expire. |
| accounting | *(separate service)* | — | Reads invoices via `BusinessService.GetInvoice`. |
| telemetry | *(separate service)* | — | Reads shipments via `BusinessService.GetActiveShipmentByDriver`. |

### Local versus AWS

| | Local | Production |
|---|---|---|
| PostgreSQL | `postgres:16-alpine` containers, ports 5432 and 5433 | AWS RDS, one instance per service, `DB_SSLMODE=require` |
| MongoDB | `mongo:7` container, port 27017 | MongoDB Atlas or DocumentDB, **a new cluster** |

> **The MongoDB is new and empty.** It is not the monolith's cluster. Both Mongo
> services refuse to start against the legacy target — see §6.

---

## 2. authentication — PostgreSQL `karlo_auth`

Migration: [`authentication-service/migrations/000001_init.up.sql`](../../migrations/000001_init.up.sql)

The legacy system had one `users` collection carrying three separate concerns:
the company, the person, and the session. Splitting them is what makes the
permission logic legible.

### `companies`
One row per tenant.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `legacy_id` | VARCHAR(24) UNIQUE | The Mongo ObjectId, so a later migration can map references still held elsewhere. |
| `name`, `role` | VARCHAR | `role` is shipper, transporter, or both. |
| `npwp`, `no_siup`, `no_tdp` | VARCHAR | Indonesian tax and trade registration numbers. |
| `settings` | JSONB | Per-company business toggles. Read by the business service over gRPC; see §5. |
| `email_recipients` | TEXT[] | Addresses copied on document mail. |
| `is_verified`, `is_suspended` | BOOLEAN | |
| `deleted_at` | TIMESTAMPTZ | Soft delete. |

### `users`
One row per person who can authenticate.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `company_id` | UUID → companies | The tenant. |
| `parent_id` | UUID → users | Who created this account. **NULL means a root account, which bypasses module permission checks.** |
| `email`, `username`, `phone` | CITEXT / VARCHAR | Case-insensitive. Unique among live accounts only — see the index note below. |
| `password_hash` | VARCHAR(255) | bcrypt. Carries `json:"-"` in the model so it cannot be serialised into a response by accident. |
| `role` | VARCHAR(32) | superadmin, admin, shipper, transporter, driver, manager, warehousePic, merchant. |
| `account_type` | VARCHAR(32) | `mainAccount` or `subAccount`. |
| `permission` | JSONB | `{module: {action: bool}}`. Applied only to non-root accounts. |
| `deleted_at` | TIMESTAMPTZ | Soft delete. |

Uniqueness is enforced by **partial** indexes:

```sql
CREATE UNIQUE INDEX uq_users_email ON users (email)
  WHERE deleted_at IS NULL AND email IS NOT NULL;
```

A soft-deleted user must not block reuse of their email, which a plain unique
constraint would.

### `sessions`
One row per issued credential, so a token can be revoked individually.

| Column | Notes |
|---|---|
| `token_id` | UUID, matches the JWT's `jti`. |
| `refresh_token_hash` | SHA-256 hex. The token itself is never stored, so a database leak yields no usable sessions. |
| `single_device` | The legacy `tokenKapps` rule: a new login evicts the previous one. |
| `expires_at`, `revoked_at` | Revocation is a timestamp, not a delete, so history survives. |

The legacy design stored one token string on the user row: a second login
silently invalidated the first, and there was no way to list active sessions.

### `device_tokens`
One row per device, not one token per user. A driver with a phone and a tablet
previously received notifications only on whichever logged in last.

`failed_at` records a delivery rejection so dead tokens are pruned rather than
retried forever.

### `api_keys`
Replaces the ten 32-character tokens hardcoded in the monolith's constants file.
Keys are stored as SHA-256 hashes; `key_prefix` keeps the first 8 characters in
clear so an operator can identify a key in a list without being able to use it.

### `user_documents`
The legacy user row carried ~16 paired columns (`fotoKtp`/`isKtpVerified`,
`fotoSiup`/`isSiupVerified`, …). One row per document instead, so adding a
document type is data rather than a migration.

### `collaboration_invites`, `auth_audit_log`
Invitations with hashed accept tokens, and an audit trail written on every
login, logout, password change, permission change and suspension. The legacy
system recorded none of these, which made "who changed this account"
unanswerable.

---

## 3. masterdata — MongoDB `karlo_masterdata`

**Every collection carries an `md_` prefix.** The legacy Mongoose models occupy
the unprefixed names (`trucks`, `warehouses`, `customers`, `points`), so the
prefix guarantees the two systems cannot collide even in one database.

Indexes are created at startup by
[`EnsureIndexes`](https://github.com/karlo/masterdata-service/blob/main/internal/config/database.go).

### `md_catalog_items` — the global catalogues
Twenty catalogues share one collection, distinguished by `kind`. A rate card's
tariff table and a province's code have nothing in common, so catalogue-specific
fields live in `attributes` and a new catalogue needs no schema change.

| Field | Notes |
|---|---|
| `kind` | One of the 20 values in [`models.AllCatalogKinds`](https://github.com/karlo/masterdata-service/blob/main/internal/models/models.go). |
| `code` | The stable business identifier, unique within a kind. Imports and integrations match on it, so it must not change. |
| `name`, `description`, `active`, `sortOrder` | |
| `parentId` | Hierarchy: city → province, district → city. |
| `attributes` | Free-form. A truck type carries `maxWeightKg`; a currency carries `symbol`. |

Kinds: brand, cargoType, cargoTruckCapacity, currency, district, item,
itemCharacter, itemType, kota, paymentType, pricingType, provinsi, rateCard,
requirement, route, truckBody, truckHead, truckType, faq, jobVacancy.

```
{ kind: 1, code: 1 }  UNIQUE
{ kind: 1, active: 1, name: 1 }
{ kind: 1, parentId: 1 }
```

### `md_trucks` — company vehicles

| Field | Notes |
|---|---|
| `companyId` | **The tenant key. Every query filters on it.** A query that does not is a leak between companies. |
| `policeNumber` | Unique within a company. |
| `truckTypeId`, `truckHeadId`, `truckBodyId`, `brandId` | ObjectIds into `md_catalog_items`. |
| `driverIds` | **Authentication-service UUIDs, held as strings** — they live in another database. |
| `documents` | STNK, KIR, insurance with expiry dates. |

### `md_warehouses` — loading and unloading points

`location` is GeoJSON `{type: "Point", coordinates: [lng, lat]}`. Note the
order: GeoJSON is **longitude first**, the reverse of how people say it.
[`NewGeoPoint(lat, lng)`](https://github.com/karlo/masterdata-service/blob/main/internal/models/models.go) takes
them the spoken way round so the transposition cannot happen by accident, and a
test pins it.

`geofenceRadius` (metres) drives the business service's geofenced completion
check. A `2dsphere` index backs the proximity query.

### `md_truck_groups`, `md_customers`, `md_points`, `md_saved_routes`
Fleet partitions, a company's client register, named waypoints, and reusable
origin-destination pairs with their planned polyline.

---

## 4. business — PostgreSQL `karlo_business`

Migration: [`business-service/migrations/000001_init.up.sql`](https://github.com/karlo/business-service/blob/main/migrations/000001_init.up.sql)

### `agreements` and `agreement_rates`
The legacy system buried price lines in an array inside the agreement document,
which made "what did we charge on this lane" unanswerable without scanning every
agreement. They are rows here, one per origin-destination-trucktype combination.

`verified` records the shipper's explicit sign-off; companies with
`activeAgreementVerifiedOnly` refuse to order against an unverified agreement.

### `orders`
`order_kind` separates flows the monolith kept in one collection with divergent
branches: `standard` freight, `empty` repositioning trips (*ngosong*), and
`threepl` sub-contracts. `parent_order_id` links a child to the order it was
spawned from.

**Only `status_code` is stored.** The legacy schema kept `statusCode`, `status`
and `statusAlias` as three hand-written columns that regularly disagreed; the
display strings are derived from the code.

### `order_status_history`
Every status change, with who made it and what drove it (`user`, `system`,
`cron`, `geofence`, `integration`). The legacy system overwrote status in place
and kept no history, so "when did this order become late" had no answer.

### `shipments`
One physical execution of an order, separate because an order can be re-run
after a failed attempt. Nine timestamp columns track the driver-app flow step by
step; `loading_within_geofence` / `unloading_within_geofence` record whether
each arrival was inside the warehouse boundary — **recorded always, enforced
only when the company enables it**, so turning enforcement on later does not
invalidate the history recorded while it was off.

### `invoices` and `invoice_lines`
All amounts are `NUMERIC(18,2)`, never floating point. PPN is added to the bill
and PPH23 is withheld from it; both are computed in one place
([`Invoice.Recalculate`](https://github.com/karlo/business-service/blob/main/internal/models/models.go)) with
the signs pinned by test.

`invoice_lines` is its own table with `UNIQUE (invoice_id, order_id)`, so an
order cannot be billed twice on one invoice, and re-invoicing does not silently
detach the old lines.

### `number_sequences`
Human-facing document numbers (`ORD-2026-000123`) reset per year. The legacy
"uniqid" collection read-then-wrote and could hand the same number to two
concurrent requests. This uses an atomic function:

```sql
INSERT INTO number_sequences (scope, period, current_value) VALUES ($1, $2, 1)
ON CONFLICT (scope, period)
DO UPDATE SET current_value = number_sequences.current_value + 1
RETURNING current_value;
```

The `ON CONFLICT DO UPDATE` holds a row lock for the duration, so two concurrent
callers cannot receive the same number.

---

## 5. notification — MongoDB `karlo_notification`

**Every collection carries an `nt_` prefix.** The legacy models occupy
`notifications`, `messages`, `messagegroups` and `messagetemplates`, all of
which still hold live data the monolith reads.

### `nt_notifications`
One document **per recipient**, so read state is per person rather than shared.

| Field | Notes |
|---|---|
| `userId` | The single recipient. An audience is expanded into one document each. |
| `event`, `title`, `body` | Copy rendered from the template registry, not supplied by the caller. |
| `subjectId`, `subjectType` | The deep-link target. |
| `deliveries[]` | Per-channel outcome, so an undelivered push is diagnosable rather than invisible. |
| `idempotencyKey` | `<caller key>|<userId>`, sparse-unique. This is what makes business-service retries safe. |

**The in-app record is the source of truth**, written before any delivery is
attempted. In the monolith a Mongo `post('save')` hook fired FCM, so a delivery
failure was invisible and an undeliverable notification was indistinguishable
from one nobody raised.

### `nt_otps`
`codeHash` is SHA-256 — the legacy implementation stored codes in clear.
`attempts` caps brute force; a TTL index expires documents after 24 hours.

### `nt_inbound_messages`
Raw WhatsApp webhook payloads, stored **before** processing and deduplicated on
`(provider, providerId)` because Meta redelivers freely. The legacy handler
logged the body and spawned a goroutine that did nothing, so every inbound
customer message was lost.

### `nt_message_groups`, `nt_messages`, `nt_tickets`, `nt_ticket_events`
In-app chat threads with per-person `readBy`, and support tickets with an audit
trail.

---

## 6. Cross-service references

Because each service owns its store, a reference to another service's data is a
**bare identifier with no foreign key**. The column type records which kind:

| Reference | Type | Lives in | Resolved via |
|---|---|---|---|
| user id, company id | `UUID` | authentication | `AuthService.GetUser`, `GetUsers`, `GetCompany` |
| truck id, warehouse id | `VARCHAR(24)` Mongo ObjectId hex | masterdata | `MasterDataService.GetTruck`, `GetWarehouse` |
| catalogue ids | `VARCHAR(24)` | masterdata | `ResolveCatalogItems`, `ValidateReferences` |
| order id, invoice id | `UUID` | business | `BusinessService.GetOrder`, `GetInvoice` |

```
business.orders
  ├── shipper_company_id       UUID     → auth.companies
  ├── transporter_company_id   UUID     → auth.companies
  ├── driver_user_id           UUID     → auth.users
  ├── truck_id                 ObjectId → masterdata.md_trucks
  ├── origin_warehouse_id      ObjectId → masterdata.md_warehouses
  └── cargo_type_id            ObjectId → masterdata.md_catalog_items
```

### The consistency trade

There is no database-level integrity across services. Three mitigations:

1. **Validate at write time.** Before committing an order, the business service
   calls `ValidateReferences` so a bad catalogue id is refused rather than
   surfacing as a blank field on a screen weeks later.
2. **Soft delete everywhere.** Nothing referenced is ever hard-deleted, so a
   historic order still resolves the truck it used.
3. **Fail loud on resolution.** A reference that cannot be resolved produces an
   error, not a silent empty value.

### Legacy ID mapping

Every Postgres table carries `legacy_id VARCHAR(24) UNIQUE` holding the original
Mongo ObjectId. No ETL ships with this scaffold — the decision was to start
Mongo fresh with master data only — but the column is there so a later migration
can map references that still exist in other systems.

---

## 7. The legacy database is unreachable by construction

Both MongoDB services apply two defences, neither configurable
([guard.go](https://github.com/karlo/masterdata-service/blob/main/internal/config/guard.go)):

**1. Target guard.** The connection is refused *before the driver is
constructed* if the URI names the legacy Atlas cluster (`cluster0-ndqn7`), or
the database is `prod`, `test` or `local` — whether named in `MONGO_DATABASE` or
in the URI path. No connection attempt happens at all.

**2. Collection prefixes.** `md_` and `nt_`. The legacy models own the
unprefixed names, so even a target that slipped past the first check could not
overwrite them.

Removing either requires editing the guard file. Covered by
[`guard_test.go`](https://github.com/karlo/masterdata-service/blob/main/internal/config/guard_test.go).

The seed loader ([`cmd/seed`](https://github.com/karlo/masterdata-service/blob/main/cmd/seed/main.go)) adds a
third: it is a dry run by default and writes only with `-confirm`, and its
writes are upserts keyed on `(kind, code)` so running it twice equals running it
once. It never deletes.

> **Outstanding:** the `OLD/` tree has live Atlas credentials for the `prod`
> cluster committed in `karlo_be/src/config`, plus ten hardcoded API tokens in
> `src/constants`. Both need rotating independently of this work.

---

## 8. Migrations

Postgres uses [golang-migrate](https://github.com/golang-migrate/migrate) with
versioned up/down pairs. GORM never creates schema:
`DisableForeignKeyConstraintWhenMigrating` is set so the ORM cannot drift from
what the migration files declare.

```bash
make migrate                                    # both databases
cd business-service && make migrate-create NAME=add_something
```

MongoDB has no migration tool. Indexes are created at startup by
`EnsureIndexes`, which is idempotent and cheap when the index already exists —
an index the service depends on should not be able to go missing.
