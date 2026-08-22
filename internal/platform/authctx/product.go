package authctx

// Product identifies which Karlo product a service belongs to.
//
// One identity and one company serve both products, but almost nothing else is
// shared: the role vocabularies do not overlap, and both products have modules
// called dashboard, notifications, reports, masterData and customer meaning
// entirely different things. Every entitlement and permission is therefore
// qualified by product, and a service declares which one it is at startup.
type Product string

const (
	ProductTMS Product = "tms"
	ProductFMS Product = "fms"

	// ProductShared owns entitlements belonging to neither product. Accounting
	// and telemetry are separate services both products consume, so duplicating
	// their entitlement per product would let the two disagree about whether a
	// company holds them.
	ProductShared Product = "shared"
)

// PermissionSpec describes one entry in a product's permission catalogue.
type PermissionSpec struct {
	// Key is what is granted to a user, in `subject.action` form.
	Key string

	// Feature is the company entitlement that gates this permission — and it
	// is NOT derivable from the key.
	//
	// This is the part most likely to be got wrong by assumption. In FMS,
	// `fuel.view` is gated by the `live` feature, `dashboard.ai` by
	// `ai_dashboard`, `reports.custom` by `custom_report`, and
	// `dashcams.manage` by `camera`. Splitting the key on its dot and treating
	// the prefix as the feature would gate several permissions against
	// entitlements that do not exist, silently denying everyone.
	//
	// Empty means UNGATED: the permission needs no entitlement, only the user
	// grant. FMS uses this for its master-data and administration surface —
	// managing vehicles, drivers, users and roles is always available to a
	// company that has the product at all.
	Feature string

	// Group and Label drive the permission editor.
	Group string
	Label string
}

// Catalog is one product's permission catalogue, keyed by permission key.
type Catalog map[string]PermissionSpec

// catalogs holds every product's catalogue.
//
// These live in code rather than in a table on purpose: the catalogue describes
// what the code enforces, so storing it separately would let the two drift, and
// a permission that exists in the database but nowhere in the code grants
// nothing while appearing to grant something.
var catalogs = map[Product]Catalog{
	ProductTMS: tmsCatalog,
	ProductFMS: fmsCatalog,
}

// CatalogFor returns a product's permission catalogue.
func CatalogFor(product Product) Catalog { return catalogs[product] }

// FeatureFor returns the entitlement gating a permission, and whether the
// permission is known at all.
func FeatureFor(product Product, key string) (feature string, known bool) {
	spec, ok := catalogs[product][key]
	if !ok {
		return "", false
	}
	return spec.Feature, true
}

// FeaturesFor returns every distinct entitlement a product's catalogue
// references — the sellable list, for an entitlement administration screen.
func FeaturesFor(product Product) []string {
	seen := map[string]bool{}
	var out []string
	for _, spec := range catalogs[product] {
		if spec.Feature == "" || seen[spec.Feature] {
			continue
		}
		seen[spec.Feature] = true
		out = append(out, spec.Feature)
	}
	return out
}

// IsKnownPermission reports whether a key exists in a product's catalogue.
//
// Used when validating a grant, so a typo is refused at the point it is made
// rather than becoming a permission that silently never matches.
func IsKnownPermission(product Product, key string) bool {
	_, ok := catalogs[product][key]
	return ok
}
