# Business Documentation

What each service is responsible for, and how a flow moves across them.

---

## 1. Division of responsibility

The split follows one rule: **a service owns a decision, not just a table.** If
two services could both plausibly decide something, exactly one of them does and
the other asks.

| Service | Owns the decision about | Explicitly does *not* decide |
|---|---|---|
| **authentication** | Who a caller is, which company they belong to, what their role and permissions are, whether a session is still valid. | Anything about orders, trucks or notifications. |
| **masterdata** | What reference data exists, which trucks and warehouses a company has, which drivers are paired with which vehicle. | Whether a truck may be used for a given order — that is a business rule. |
| **business** | Whether an order may move to a state, what it costs, who may see it, when an invoice is payable. | Who the caller is (asks auth), whether a truck exists (asks masterdata), how to reach someone (tells notification). |
| **notification** | Which channels an event uses, what the message says, when to stop retrying. | What happened, and who cares — the caller states both. |
| accounting *(separate)* | The ledger, payment reconciliation. | Freight billing, which business owns. |
| telemetry *(separate)* | Vehicle positions, geofence crossings. | Whether a crossing advances a shipment — it reports, business decides. |

---

## 2. authentication — identity and access

**HTTP** `:5001` · **gRPC** `:6001` · Postgres `karlo_auth`

### Flows

**Registration.** A registration with no parent and no company creates a *new
tenant*: a company row and a root account together. A registration with a parent
creates a sub-account inside that parent's company, inheriting a permission map.
Identifier availability is checked first, so a collision is a clear 400 rather
than a constraint violation.

**Login.** One query across email, username and phone — the legacy version tried
each in three sequential queries, which leaked through response timing which
field matched. Failures are uniform: the same error whatever went wrong, and a
dummy bcrypt comparison runs even when no user matched, so neither the message
nor the timing reveals whether an account exists. Failed attempts are counted
per identifier and rate limited.

On success the service issues a short-lived RS256 access token and a long-lived
refresh token, and opens a **session** row. Roles in the single-device set
(shipper, transporter, manager) evict their previous session, reproducing the
legacy `tokenKapps` rule.

**Refresh.** The refresh token is rotated on every use: the old one stops
working the moment a new pair is issued, so a stolen token is usable at most
once.

**Permission change.** The permission map is embedded in issued tokens, so a
change only takes effect once those are gone. Setting permissions therefore
revokes the target's sessions, forcing a refresh. The same applies to a password
change and to suspension — a password change that leaves old sessions alive does
not actually lock anyone out.

### What it serves other services

| RPC | Called by | For |
|---|---|---|
| `ValidateToken` | all | API keys and single-device sessions, which cannot be verified locally |
| `GetUser`, `GetUsers` | business, notification | Names, roles, language |
| `GetCompany` | business | The settings that govern order and invoice rules |
| `ListCompanyMembers` | notification | Expanding "the transporter's dispatchers" into people |
| `ResolveDeliveryTargets` | notification | Push tokens, emails, phones — so contact details are never duplicated out of this database |

---

## 3. masterdata — reference data

**HTTP** `:5002` · **gRPC** `:6002` · MongoDB `karlo_masterdata`

Two families with different access rules:

**Global catalogues** are shared by every company: truck types, cargo types,
item types, provinces, cities, currencies, payment terms. **Readable by any
authenticated user, writable only by platform staff** — a company editing them
would change what every other company sees.

**Company catalogues** belong to one company: trucks, truck groups, warehouses,
customers, points, saved routes. Scoped to the caller's company, always taken
from the token and never from the request.

### Flows

**Registering a truck** validates its catalogue references before writing, so a
truck cannot be stored pointing at a truck type that does not exist.

**Driver pairing** (`POST /trucks/:id/drivers`) is `$addToSet`, so the call is
idempotent. This is the record the business service consults before allowing an
order to be assigned.

**Warehouse geofences.** Each warehouse carries a radius in metres. The business
service reads it to decide whether a driver reporting arrival is actually at the
gate.

### Reads without a tenant filter

Two methods deliberately skip the company filter: `FindByIDAnyCompany` for
trucks and warehouses. They exist only for the gRPC read path, where the
business service already holds an id it obtained legitimately and a shipment
spans *two* companies' warehouses — so there is no single tenant to filter by.
They are named so that reaching for one by accident is hard.

---

## 4. business — the transactional core

**HTTP** `:5003` · **gRPC** `:6003` · Postgres `karlo_business`

This is where the monolith was weakest: 183 routes resolving to 28 handlers, 46
of them sharing one generic update that wrote whatever the request body
contained.

### Order lifecycle

```
draft ──submit──▶ submitted ──approve──▶ approved ──plan──▶ readyToPlan
  │                   │                                          │
  │                   └──reject──▶ rejected                   assign
  │                                                              │
  └──cancel──▶ cancelled                                     assigned
                                                                 │
                                              (shipment starts) inTransit
                                                                 │
                                              (shipment finishes) delivered
                                                                 │
                                                    ──complete──▶ completed
```

Who may do what is part of the machine, not scattered across handlers:

| Transition | Who |
|---|---|
| draft → submitted | shipper |
| submitted → approved / rejected | **transporter** |
| approved → readyToPlan | transporter |
| readyToPlan → assigned | transporter |
| delivered → completed | shipper or warehouse PIC |
| anything → cancelled | depends on state; a shipper past approval must *request* cancellation |

Platform administrators may take any listed transition, so a stuck order never
requires a database edit — which is what the legacy `reset-status-parent`
endpoints existed for.

**One endpoint replaces 46.** `PUT /orders/:id/status` takes a destination; the
machine decides legality. `GET /orders/:id/transitions` returns the moves
available to *this* caller, so a client renders only buttons that will work.

Transitions are **compare-and-set**: the update applies only if the order is
still in the expected state. Two managers pressing approve at once cannot both
succeed. The legacy code read, decided, then wrote, so the second silently
overwrote the first.

Concretely refused where the monolith allowed it: a driver approving an order, a
shipper assigning a driver, an order skipping draft → completed, reopening a
completed order.

### Shipment lifecycle

```
assigned → toLoading → atLoading → loadingApproved → loading → loaded
         → toUnloading → atUnloading → unloadingApproved → unloading
         → unloaded → finished
```

The driver reports movement; the **warehouse PIC approves**. That separation was
lost in the monolith, where `ttd-loading`, `checklist-loading` and `start-loading`
all routed to one handler. A driver cannot approve their own loading or sign off
their own delivery.

**Arrival and geofencing.** Reporting arrival requires a position. The service
fetches the warehouse from masterdata, computes the haversine distance, and
records whether the driver was inside the radius. Enforcement is separate: the
arrival is refused only if the shipper's company has `finishWithGeofencing` set.
If masterdata is unreachable the arrival is still recorded with the geofence
result unknown — **a master data outage must not strand a driver at a gate.**

**Order and shipment stay in step.** `toLoading` moves the order to `inTransit`;
`finished` moves it to `delivered`. An order reading "assigned" while its
shipment is halfway to the unloading point is exactly the inconsistency the
legacy system produced.

### Agreements

A shipper proposes; the **transporter** decides. Once active, the shipper may
`verify` it — the explicit sign-off that companies with
`activeAgreementVerifiedOnly` require before ordering against it. An hourly
sweep expires agreements past their validity and notifies the shipper; the
notification is keyed by date so the sweep cannot re-notify for the same day.

Placing an order against an agreement checks `IsUsable`: active, in date
(inclusive at both ends), and verified if the company demands it.

### Invoices

Creating one enforces three things the monolith checked none of:
1. Every order is complete or delivered.
2. Every order was carried by the billing company and belongs to the named shipper.
3. No order is already on a live invoice.

Tax rates come from the billing company's settings at creation time, so a rate
change applies to new invoices without touching issued ones.

```
draft → issued → submitted → verified → paid
```

**The transporter issues and submits; the shipper verifies and pays.** Letting
the biller mark their own invoice paid is how receivables quietly stop being
real.

---

## 5. notification — outbound messaging

**HTTP** `:5004` · **gRPC** `:6004` · MongoDB `karlo_notification`

### What it absorbed

The crosscheck against the monolith found notifications were **not** contained
in `communication-service-be`. Four separate systems existed:

| Was | Where | Sites |
|---|---|---|
| `Notification` model + FCM `post('save')` hook | karlo_be, karlo_order | **70 + 47** creation sites |
| `Message`/`MessageGroup` chat with its own FCM hook | karlo_be, karlo_order | separate, unconnected |
| `nodemailer`, called inline | 5 controllers | no shared template |
| WhatsApp, OTP, tickets | communication-service-be | the only part that was a service |

All four are here. The ~117 inline `Notification.create` calls become one
`Notify` RPC.

### The contract

A caller states **what happened** and **who should hear about it**:

```go
notifier.Notify(ctx, clients.Event{
    Type:     notificationv1.EventType_EVENT_TYPE_ORDER_ASSIGNED_DRIVER,
    Subject:  clients.Subject{ID: order.ID.String(), Type: "order"},
    Audience: clients.ToUsers(driverID.String()),
    Params:   map[string]any{"orderNumber": order.OrderNumber},
    ActorID:  actor.UserID.String(),
    IdempotencyKey: fmt.Sprintf("order:%s:assigned:%s", orderID, driverID),
})
```

No business code names FCM, SMTP or WhatsApp, and none writes message copy.

**Audiences** are resolved here, not by the caller: `ToUsers`,
`ToCompanyRoles(companyID, roles...)`, `ToPhone`. Expanding a company role into
people is a call to the authentication service, so business logic never fetches
a user list just to send a message.

**Copy** comes from the [template registry](https://github.com/karlo/notification-service/blob/main/internal/templates/templates.go),
which maps each event to its default channels and its wording per language. A
missing parameter is an **error**, not a blank substitution — sending "Order  is
awaiting your approval" is worse than not sending.

### Delivery order

1. Resolve the audience, excluding the actor — nobody is notified of their own action.
2. Render copy **per recipient**, since language is per user.
3. **Write the in-app record.** This is the source of truth.
4. Attempt each channel, bounded by a worker pool.
5. Record each outcome on the notification.

A delivery failure never fails the RPC. In the monolith a Mongo save hook drove
FCM, so a failure was invisible and the notification was simply lost.

Dead push tokens are distinguished from transient failures and deactivated
rather than retried forever.

### OTP

`crypto/rand` (not the legacy unseeded `math/rand`), stored as a SHA-256 hash,
capped attempts, constant-time comparison, and a resend cooldown — the legacy
endpoint had none, so it could send unlimited WhatsApp messages to any number.

### WhatsApp webhook

The payload is **persisted before the handler returns**, deduplicated on the
provider message id because Meta redelivers freely. An unparseable body is
acknowledged with 200 (it will not become parseable on retry); a storage failure
returns 500 so Meta redelivers.

---

## 6. A flow end to end

**A shipper places an order and it is delivered.**

```
 1. Shipper POSTs /api/v1/orders                        → business
 2. business validates catalogue refs                   → masterdata (gRPC)
 3. business reads agreement + company settings         → auth (gRPC)
 4. business writes the order, status=submitted
 5. business raises ORDER_CREATED                       → notification (gRPC)
 6. notification expands "the transporter's dispatchers" → auth (gRPC)
 7. notification writes inboxes, sends push

 8. Transporter PUTs /orders/:id/status {approved}      → business
 9. …then {readyToPlan}, then PUT /orders/:id/assign
10. business confirms the driver is paired with the truck → masterdata (gRPC)
11. business creates the shipment, notifies the driver

12. Driver PUTs /shipments/:id/status {toLoading}       → business
13. business advances the order to inTransit, notifies the shipper
14. Driver reports {atLoading} with a position
15. business fetches the warehouse geofence             → masterdata (gRPC)
16. …records whether they were inside; enforces only if the company asked
17. Warehouse PIC approves; loading proceeds; the same at the far end
18. PIC PUTs {finished} → order becomes delivered, shipper notified

19. Shipper PUTs /orders/:id/status {completed}
20. Transporter POSTs /api/v1/invoices covering the order
21. business checks it is complete, theirs, and not already billed
22. business reads tax rates                            → auth (gRPC)
23. Shipper verifies and pays; accounting reads it      → business (gRPC)
```

Telemetry runs alongside: it asks business `GetActiveShipmentByDriver` to
correlate a position, and reports crossings via `ReportGeofenceEvent`. A
crossing is **evidence, not a command** — it records that the truck arrived but
does not advance the shipment. Drivers confirm arrival themselves; conflating
the two would let a GPS glitch move a shipment forward.

---

## 7. Cross-cutting rules

**Identity.** RS256. The authentication service holds the private key and is the
only party that can mint a token; everyone else verifies locally with the public
key — no network hop per request, and no shared secret a compromised service
could use to forge identities. The algorithm is pinned, closing the
`alg`-confusion hole the monolith had.

**Tenancy** is enforced *in the query*, with the company id from the token and
never from the request. The monolith's `GetAllOrder` applied no scoping at all.

**Writes are allowlisted.** Every partial update projects the body through an
explicit field map. Filter and sort fields are allowlisted too — an
un-allowlisted name reaching an `ORDER BY` lets a caller sort by a column they
cannot read.

**Failure posture.** Notifications are best-effort and never fail the operation
they describe. Master data lookups degrade rather than block. Authentication
failures are hard, because the alternative is serving data to an unidentified
caller.

**Error codes.** A refused state change is **409**, not 400: the request was
well formed, but the resource is not in a state that permits it, and the client
should refresh rather than reformat.
