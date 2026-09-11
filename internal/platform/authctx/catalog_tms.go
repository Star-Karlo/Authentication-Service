package authctx

// The TMS permission catalogue.
//
// Unlike FMS, TMS's gating feature is currently the same as the key's prefix in
// every case — `order.read` is gated by `order`. That is a property of this
// catalogue, not of the model, and it is stated explicitly rather than derived
// so that the first TMS permission needing a different gate is a one-line
// change here instead of a rewrite of the checking logic.
var tmsCatalog = Catalog{
	"order.read":          {Key: "order.read", Feature: "order", Group: "Orders", Label: "View orders"},
	"order.create":        {Key: "order.create", Feature: "order", Group: "Orders", Label: "Create orders"},
	"order.update":        {Key: "order.update", Feature: "order", Group: "Orders", Label: "Edit draft orders"},
	"order.cancel":        {Key: "order.cancel", Feature: "order", Group: "Orders", Label: "Cancel orders"},
	"order.approve":       {Key: "order.approve", Feature: "order", Group: "Orders", Label: "Approve or reject orders"},
	"order.assignDriver":  {Key: "order.assignDriver", Feature: "order", Group: "Orders", Label: "Assign a driver and truck"},
	"order.readyToPlan":   {Key: "order.readyToPlan", Feature: "order", Group: "Orders", Label: "Mark ready to plan"},
	"order.requestDriver": {Key: "order.requestDriver", Feature: "order", Group: "Orders", Label: "Request a driver (3PL)"},

	// Uang sangu. Split from order.update into its own keys because a company
	// decides separately who may touch money: the same person who edits an
	// order is often NOT the person allowed to set what a driver is handed in
	// cash, and some companies put it with sales while others put it with
	// finance. Three keys rather than one, because seeing the figure, setting
	// it, and committing it to the driver are three different trusts.
	"order.allowance.read":     {Key: "order.allowance.read", Feature: "order", Group: "Driver allowance", Label: "View driver allowance"},
	"order.allowance.write":    {Key: "order.allowance.write", Feature: "order", Group: "Driver allowance", Label: "Set driver allowance"},
	"order.allowance.finalise": {Key: "order.allowance.finalise", Feature: "order", Group: "Driver allowance", Label: "Finalise driver allowance"},

	// Dispatch.
	//
	// dispatch.reroute is gated by `dispatch` like its neighbours, NOT by the
	// paid routing.advanced entitlement, and the distinction is load-bearing.
	//
	// A permission answers "is this PERSON allowed to press the button"; a
	// feature answers "has the COMPANY bought it". They fail differently and a
	// client must be able to tell them apart: the first is fixed by an
	// administrator, the second by a sales conversation.
	//
	// Naming routing.advanced here collapsed the two. RequireModule calls
	// HasPermission, which refuses a permission whose feature the company
	// lacks — so an unentitled company got 403 "Access Denied" from the
	// middleware and never reached the handler that answers 402. The
	// entitlement check lives in the handler, where it can say so properly.
	"dispatch.read":    {Key: "dispatch.read", Feature: "dispatch", Group: "Dispatch", Label: "View candidate trucks and routes"},
	"dispatch.assign":  {Key: "dispatch.assign", Feature: "dispatch", Group: "Dispatch", Label: "Assign a truck to an order"},
	"dispatch.reroute": {Key: "dispatch.reroute", Feature: "dispatch", Group: "Dispatch", Label: "Re-plan a route on demand"},

	// Form configuration. Deciding which fields an agreement or order demands
	// changes what every colleague sees, so it is an administrative act rather
	// than part of using the forms.
	"config.fields.read":  {Key: "config.fields.read", Feature: "configuration", Group: "Administration", Label: "View form configuration"},
	"config.fields.write": {Key: "config.fields.write", Feature: "configuration", Group: "Administration", Label: "Change which fields are required"},

	"agreement.read":    {Key: "agreement.read", Feature: "agreement", Group: "Agreements", Label: "View agreements"},
	"agreement.create":  {Key: "agreement.create", Feature: "agreement", Group: "Agreements", Label: "Create agreements"},
	"agreement.update":  {Key: "agreement.update", Feature: "agreement", Group: "Agreements", Label: "Edit agreements"},
	"agreement.approve": {Key: "agreement.approve", Feature: "agreement", Group: "Agreements", Label: "Approve, reject or verify"},
	"agreement.cancel":  {Key: "agreement.cancel", Feature: "agreement", Group: "Agreements", Label: "Cancel agreements"},

	// Versioning and approval, from the PRD.
	//
	// agreement.revise and agreement.approveRevision are deliberately separate
	// from agreement.update and agreement.approve. The existing pair governs
	// the SHIPPER-facing decision — accepting an agreement offered to you —
	// while these govern the transporter's own internal control: Sales
	// proposes a price change, a Sales Manager signs it off. A company that
	// gave one role both would have an approval step that costs a click and
	// prevents nothing, so the service also refuses a self-approval outright.
	"agreement.revise":          {Key: "agreement.revise", Feature: "agreement", Group: "Agreements", Label: "Renew or amend an agreement"},
	"agreement.approveRevision": {Key: "agreement.approveRevision", Feature: "agreement", Group: "Agreements", Label: "Approve or reject an amendment"},
	"agreement.priceHistory":    {Key: "agreement.priceHistory", Feature: "agreement", Group: "Agreements", Label: "View price history"},

	"invoice.read":    {Key: "invoice.read", Feature: "invoice", Group: "Invoicing", Label: "View invoices"},
	"invoice.create":  {Key: "invoice.create", Feature: "invoice", Group: "Invoicing", Label: "Create invoices"},
	"invoice.update":  {Key: "invoice.update", Feature: "invoice", Group: "Invoicing", Label: "Change invoice status"},
	"invoice.approve": {Key: "invoice.approve", Feature: "invoice", Group: "Invoicing", Label: "Verify and settle"},
	"invoice.export":  {Key: "invoice.export", Feature: "invoice", Group: "Invoicing", Label: "Export invoices"},

	"shipment.read":            {Key: "shipment.read", Feature: "shipment", Group: "Shipments", Label: "View shipments"},
	"shipment.update":          {Key: "shipment.update", Feature: "shipment", Group: "Shipments", Label: "Advance a shipment"},
	"shipment.verifyLoading":   {Key: "shipment.verifyLoading", Feature: "shipment", Group: "Shipments", Label: "Approve loading"},
	"shipment.verifyUnloading": {Key: "shipment.verifyUnloading", Feature: "shipment", Group: "Shipments", Label: "Approve unloading"},

	"truck.read":         {Key: "truck.read", Feature: "truck", Group: "Fleet", Label: "View trucks"},
	"truck.create":       {Key: "truck.create", Feature: "truck", Group: "Fleet", Label: "Add trucks"},
	"truck.update":       {Key: "truck.update", Feature: "truck", Group: "Fleet", Label: "Edit trucks"},
	"truck.delete":       {Key: "truck.delete", Feature: "truck", Group: "Fleet", Label: "Remove trucks"},
	"truck.addDriver":    {Key: "truck.addDriver", Feature: "truck", Group: "Fleet", Label: "Pair a driver"},
	"truck.deleteDriver": {Key: "truck.deleteDriver", Feature: "truck", Group: "Fleet", Label: "Unpair a driver"},

	"warehouse.read":   {Key: "warehouse.read", Feature: "warehouse", Group: "Locations", Label: "View warehouses"},
	"warehouse.create": {Key: "warehouse.create", Feature: "warehouse", Group: "Locations", Label: "Add warehouses"},
	"warehouse.update": {Key: "warehouse.update", Feature: "warehouse", Group: "Locations", Label: "Edit warehouses"},
	"warehouse.delete": {Key: "warehouse.delete", Feature: "warehouse", Group: "Locations", Label: "Remove warehouses"},

	"customer.read":   {Key: "customer.read", Feature: "customer", Group: "Customers", Label: "View customers"},
	"customer.create": {Key: "customer.create", Feature: "customer", Group: "Customers", Label: "Add customers"},
	"customer.update": {Key: "customer.update", Feature: "customer", Group: "Customers", Label: "Edit customers"},
	"customer.delete": {Key: "customer.delete", Feature: "customer", Group: "Customers", Label: "Remove customers"},

	"dashboard.read":   {Key: "dashboard.read", Feature: "dashboard", Group: "Dashboard", Label: "View dashboard"},
	"dashboard.export": {Key: "dashboard.export", Feature: "dashboard", Group: "Dashboard", Label: "Export dashboard data"},

	"notification.read":   {Key: "notification.read", Feature: "notification", Group: "Notifications", Label: "View notifications"},
	"notification.update": {Key: "notification.update", Feature: "notification", Group: "Notifications", Label: "Manage notification settings"},

	// Ungated, matching the FMS convention: a company must be able to
	// administer its own people and reference data without a separate purchase.
	"masterData.read":   {Key: "masterData.read", Feature: "masterData", Group: "Master Data", Label: "View reference data"},
	"masterData.create": {Key: "masterData.create", Feature: "masterData", Group: "Master Data", Label: "Add reference data"},
	"masterData.update": {Key: "masterData.update", Feature: "masterData", Group: "Master Data", Label: "Edit reference data"},
	"masterData.delete": {Key: "masterData.delete", Feature: "masterData", Group: "Master Data", Label: "Remove reference data"},

	"collaboration.read":         {Key: "collaboration.read", Feature: "collaboration", Group: "Administration", Label: "View members"},
	"collaboration.inviteMember": {Key: "collaboration.inviteMember", Feature: "collaboration", Group: "Administration", Label: "Invite members"},
	"collaboration.manageMember": {Key: "collaboration.manageMember", Feature: "collaboration", Group: "Administration", Label: "Manage member permissions"},
	"collaboration.removeMember": {Key: "collaboration.removeMember", Feature: "collaboration", Group: "Administration", Label: "Remove members"},

	// Separately sold, and served by services outside this codebase. Listed
	// here so entitlement and permission for them are administered in one place.
	"accounting.read":    {Key: "accounting.read", Feature: "accounting", Group: "Accounting", Label: "View accounting"},
	"accounting.create":  {Key: "accounting.create", Feature: "accounting", Group: "Accounting", Label: "Create entries"},
	"accounting.approve": {Key: "accounting.approve", Feature: "accounting", Group: "Accounting", Label: "Approve entries"},
	"accounting.export":  {Key: "accounting.export", Feature: "accounting", Group: "Accounting", Label: "Export accounting data"},

	"telemetry.read":   {Key: "telemetry.read", Feature: "telemetry", Group: "Telemetry", Label: "View vehicle positions"},
	"telemetry.export": {Key: "telemetry.export", Feature: "telemetry", Group: "Telemetry", Label: "Export telemetry"},
}

// DefaultTMSFeatures is what a new company gets on TMS.
//
// Excludes accounting and telemetry: those are the separately sold ones, and a
// company gets them when someone decides they should.
func DefaultTMSFeatures() []string {
	return []string{
		"order", "agreement", "invoice", "shipment",
		"truck", "warehouse", "customer", "dashboard", "notification",
		// Dispatch and form configuration are part of the base product. They
		// are listed here because a feature absent from this list is a feature
		// no new company is granted, and every permission gating on it then
		// denies for everyone — silently, since a denied permission looks
		// exactly like one nobody was given.
		//
		// routing.advanced is deliberately NOT here: it is the sold one.
		"dispatch", "configuration",
		// Administration and reference data. Granted by default so gating the
		// keys that depend on them changes nothing for an existing company,
		// and so no company can lose the ability to administer itself by
		// accident. Migration 000002's backfill already granted both; they
		// were simply never declared as features.
		"collaboration", "masterData",
	}
}
