package authctx

// The FMS permission catalogue, mirroring the live production catalogue in the
// FMS codebase.
//
// Note how often the gating feature differs from the key's prefix — fuel.* is
// gated by `live`, dashboard.ai by `ai_dashboard`, dashcams.manage by `camera`.
// That indirection is the reason PermissionSpec carries Feature explicitly
// rather than deriving it.
//
// An empty Feature means the permission is always available to a company that
// has FMS at all: the master-data and administration surface.
//
// This must stay in step with the FMS service. It is duplicated rather than
// shared for the same reason everything else here is; see the note on
// internal/platform in the repository README.
var fmsCatalog = Catalog{
	"dashboard.view": {Key: "dashboard.view", Feature: "dashboard", Group: "Dashboard", Label: "View dashboard"},
	"dashboard.ai":   {Key: "dashboard.ai", Feature: "ai_dashboard", Group: "Dashboard", Label: "AI dashboard"},

	"live.view":    {Key: "live.view", Feature: "live", Group: "Live Tracking", Label: "View live tracking"},
	"live.history": {Key: "live.history", Feature: "live", Group: "Live Tracking", Label: "View trip history"},

	// Gated by `live`, not by a `fuel` feature — there is no such feature.
	"fuel.view":       {Key: "fuel.view", Feature: "live", Group: "Fuel", Label: "View fuel & cost"},
	"fuel.price_calc": {Key: "fuel.price_calc", Feature: "live", Group: "Fuel", Label: "Fuel price calculation"},

	"geofence.view":   {Key: "geofence.view", Feature: "geofence", Group: "Geofence", Label: "View geofences"},
	"geofence.manage": {Key: "geofence.manage", Feature: "geofence", Group: "Geofence", Label: "Manage geofences"},

	"controltower.view": {Key: "controltower.view", Feature: "controltower", Group: "Control Tower", Label: "View control tower"},

	"notifications.view":   {Key: "notifications.view", Feature: "notifications", Group: "Notifications", Label: "View notifications"},
	"notifications.manage": {Key: "notifications.manage", Feature: "notifications", Group: "Notifications", Label: "Manage notification rules"},

	"reports.view":   {Key: "reports.view", Feature: "reports", Group: "Reporting", Label: "View reports"},
	"reports.custom": {Key: "reports.custom", Feature: "custom_report", Group: "Reporting", Label: "Custom report builder"},
	"reports.ai":     {Key: "reports.ai", Feature: "ai_reporting", Group: "Reporting", Label: "AI reporting"},

	"camera.view": {Key: "camera.view", Feature: "camera", Group: "Camera", Label: "View cameras (TrackVision)"},

	"share_link.view":   {Key: "share_link.view", Feature: "share_link", Group: "Share Link", Label: "View share links"},
	"share_link.create": {Key: "share_link.create", Feature: "generate_link", Group: "Share Link", Label: "Generate share link"},

	"maintenance.view":   {Key: "maintenance.view", Feature: "maintenance", Group: "Fleet Management", Label: "View maintenance"},
	"maintenance.manage": {Key: "maintenance.manage", Feature: "maintenance", Group: "Fleet Management", Label: "Manage maintenance"},
	"hangars.view":       {Key: "hangars.view", Feature: "hangars", Group: "Fleet Management", Label: "View workshops"},
	"hangars.manage":     {Key: "hangars.manage", Feature: "hangars", Group: "Fleet Management", Label: "Manage workshops"},
	"license.view":       {Key: "license.view", Feature: "license", Group: "Fleet Management", Label: "View licenses"},
	"license.manage":     {Key: "license.manage", Feature: "license", Group: "Fleet Management", Label: "Manage licenses"},

	// Ungated: master data is available to any company with FMS.
	"vehicles.view": {Key: "vehicles.view", Feature: "vehicle", Group: "Master Data", Label: "View vehicles"},
	"vehicles.edit": {Key: "vehicles.edit", Feature: "vehicle", Group: "Master Data", Label: "Add / edit vehicles"},
	"drivers.view":  {Key: "drivers.view", Feature: "driver", Group: "Master Data", Label: "View drivers"},
	"drivers.edit":  {Key: "drivers.edit", Feature: "driver", Group: "Master Data", Label: "Add / edit drivers"},

	"rfid.manage": {Key: "rfid.manage", Feature: "rfid", Group: "Master Data", Label: "Manage RFID"},
	// Gated by `camera`, not by a `dashcams` feature.
	"dashcams.manage": {Key: "dashcams.manage", Feature: "camera", Group: "Master Data", Label: "Manage dashcams"},

	// Ungated: a company must be able to administer its own people.
	"users.manage": {Key: "users.manage", Feature: "administration", Group: "Administration", Label: "Manage users"},
	"roles.manage": {Key: "roles.manage", Feature: "administration", Group: "Administration", Label: "Manage roles"},
}
