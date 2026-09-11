package main

import (
	"strings"
)

// The legacy collection is one flat `users` document per person, carrying what
// are now THREE separate things: the person, the company they belong to, and
// what they may do. This file holds the rules that pull them apart.

// canonicalRole maps the legacy `role` value onto the roles this system uses.
//
// The legacy data is dirty in ways worth naming, because each one is a row that
// would otherwise be dropped or land in the wrong place:
//
//   - `warehousepic` is lowercase in the data and `warehousePic` in the code.
//   - Two rows hold `admin\x00manager` — a literal NUL byte, which Postgres
//     cannot store in a text column at all, so it must be removed before the
//     value is even looked at.
//   - `adminmanager` and `admintransporter` look like the same corruption with
//     the NUL already stripped by whatever produced the CSV.
//   - `admin` in the legacy data means a KARLO employee, not a tenant role.
//     Those become platform staff and hold no tenant role.
func canonicalRole(raw string) (role string, platformStaff bool) {
	clean := strings.ToLower(strings.TrimSpace(sanitise(raw)))

	switch clean {
	case "shipper":
		return "shipper", false
	case "transporter":
		return "transporter", false
	case "driver":
		return "driver", false
	case "warehousepic", "pic":
		return "warehousePic", false
	case "manager":
		return "manager", false
	case "merchant":
		return "merchant", false
	case "investor":
		return "investor", false
	case "admin", "superadmin":
		// A Karlo employee. Platform staff hold no tenant role; the role column
		// is NOT NULL, so a placeholder goes in and is never read for access.
		return "admin", true
	}

	// The corrupted compounds. Taking the SECOND half is deliberate: the values
	// read as "admin" concatenated with a real role, and the real role is the
	// one that describes what the person does.
	for _, suffix := range []string{"manager", "transporter", "shipper", "driver"} {
		if strings.HasSuffix(clean, suffix) && clean != suffix {
			return canonicalRoleOf(suffix), strings.HasPrefix(clean, "admin")
		}
	}

	// No role, or one nothing recognises.
	//
	// The caller flags these AND defaults them to shipper, which is a
	// compromise worth naming: the role decides which side of the order state
	// machine an account is on, so a wrong guess grants the wrong approvals.
	// Shipper is the least privileged of the two sides — a shipper cannot
	// approve or plan work — so guessing wrong here withholds ability rather
	// than granting it. The warning count is what makes the guess reviewable.
	//
	// In the real export this never fires: all four unrecognised values are
	// the `adminmanager` / `admintransporter` corruptions, and the suffix
	// matching above resolves them.
	return "", false
}

// canonicalRoleOf is only reached from the suffix matching above, which
// iterates roles that are already in their canonical spelling, so it is a
// pass-through. It exists as the single place to add a mapping if a
// differently-cased suffix ever appears in an export.
func canonicalRoleOf(s string) string { return s }

// legacyPermissions maps the flattened `permission.<module>.<action>` columns
// onto the flat catalogue keys this system grants.
//
// Not a mechanical rename. The legacy set contains modules that no longer
// exist (sp3, sppb, marketplace, service, task) and actions that were renamed.
// A key that does not appear here is DROPPED rather than carried over, because
// the catalogue refuses any key it does not declare — an unmapped legacy key
// would be dead weight that looks like a granted permission.
var legacyPermissions = map[string]string{
	"permission.order.create":                         "order.create",
	"permission.order.read":                           "order.read",
	"permission.order.update":                         "order.update",
	"permission.order.cancel":                         "order.cancel",
	"permission.order.approval":                       "order.approve",
	"permission.order.assignDriver":                   "order.assignDriver",
	"permission.order.readyToPlan":                    "order.readyToPlan",
	"permission.order.requestPickDriverToTransporter": "order.requestDriver",

	"permission.agreement.create":  "agreement.create",
	"permission.agreement.read":    "agreement.read",
	"permission.agreement.update":  "agreement.update",
	"permission.agreement.approve": "agreement.approve",

	"permission.invoice.read":          "invoice.read",
	"permission.invoice.update":        "invoice.update",
	"permission.invoice.submitInvoice": "invoice.create",
	"permission.invoice.cancel":        "invoice.update",

	"permission.truck.create":       "truck.create",
	"permission.truck.read":         "truck.read",
	"permission.truck.update":       "truck.update",
	"permission.truck.delete":       "truck.delete",
	"permission.truck.addDriver":    "truck.addDriver",
	"permission.truck.deleteDriver": "truck.deleteDriver",

	"permission.warehouse.create": "warehouse.create",
	"permission.warehouse.read":   "warehouse.read",
	"permission.warehouse.update": "warehouse.update",
	"permission.warehouse.delete": "warehouse.delete",

	"permission.warehouseManager.read":   "shipment.read",
	"permission.warehouseManager.update": "shipment.update",
	"permission.warehouseManager.verify": "shipment.verifyLoading",

	"permission.collaboration.read":         "collaboration.read",
	"permission.collaboration.inviteMember": "collaboration.inviteMember",
	"permission.collaboration.removeMember": "collaboration.removeMember",

	"permission.dashboard.read": "dashboard.read",
	"permission.report.read":    "dashboard.read",
}

// sanitise removes what Postgres cannot store and trims what nobody meant.
//
// NUL bytes are the specific hazard: a Go string holds them happily, a Postgres
// text column does not, and a COPY carrying one aborts the whole import with an
// error that names the byte offset rather than the row.
func sanitise(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	return strings.TrimSpace(s)
}

// placeholderPhones are values entered to get past a required field. They are
// not contact details and must not occupy the unique index — 08123456789 alone
// appears on 390 accounts.
var placeholderPhones = map[string]bool{
	"08123456789": true, "081234567890": true, "0812345678": true,
	"0000000000": true, "00000000000": true, "000000000000": true,
	"1234567890": true, "12345678900": true, "-": true, "0": true,
}
