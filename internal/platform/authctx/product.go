package authctx

import (
	"fmt"
	"sort"
	"strings"
)

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
	//
	// The JSON tags matter: this struct is served to the permission editor, and
	// without them Go marshals the field names verbatim — Key, Feature, Group —
	// which the client reads as undefined and renders as an empty list.
	Key string `json:"key"`

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
	Feature string `json:"feature,omitempty"`

	// Group and Label drive the permission editor.
	Group string `json:"group"`
	Label string `json:"label"`
}

// Catalog is one product's permission catalogue, keyed by permission key.
type Catalog map[string]PermissionSpec

// catalogs holds every product's catalogue.
//
// These live in code, and are SYNCED into permission_catalog at startup so a
// role editor has something to query.
//
// The direction is what matters. Code declares; the table reflects. A row in
// that table for a key the code does not declare is marked inactive and never
// honoured — because a permission that exists in the database but nowhere in
// the code grants nothing while appearing to grant something: it shows up in
// the editor, somebody ticks it, and nothing happens, with no error to find.
//
// What the table adds is presentation. A label can be reworded there without a
// deploy, which is the part that genuinely does not need to ship with code.
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

// ValidateCatalogs checks that every declared permission is gated and that
// every feature it names exists.
//
// Called at startup and failed on, deliberately.
//
// An empty Feature used to mean two different things — "deliberately not
// gated" and "nobody filled it in" — and the check treated both as "skip
// entitlement", so a forgotten one silently granted access nobody decided to
// give. That is the wrong direction for a mistake to fail in, and it is
// invisible: the permission simply works, for everyone, forever.
//
// Requiring a feature makes the author say which it is. Administration and
// reference data are gated by features granted to every company by default, so
// nothing is restricted that was not restricted before — but the check is now
// uniform, and a new key cannot skip it by omission.
func ValidateCatalogs() error {
	known := map[string]bool{}
	for _, product := range []Product{ProductTMS, ProductFMS, ProductShared} {
		for _, f := range SellableFeatures(product) {
			known[f.Name] = true
		}
	}

	var problems []string
	for product, catalog := range catalogs {
		for key, spec := range catalog {
			switch {
			case spec.Feature == "":
				problems = append(problems, fmt.Sprintf(
					"%s/%s names no gating feature; every permission must be gated, "+
						"because an ungated one skips the entitlement check entirely",
					product, key))
			case !known[spec.Feature]:
				problems = append(problems, fmt.Sprintf(
					"%s/%s is gated by %q, which is not a declared feature; "+
						"a permission gated by something that does not exist can never be granted",
					product, key, spec.Feature))
			}
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("permission catalogue is invalid:\n  - %s",
			strings.Join(problems, "\n  - "))
	}
	return nil
}
