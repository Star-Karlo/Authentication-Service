package unit

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/karlo/authentication-service/internal/platform/authctx"
)

// TestEveryGateIsSellable is the check the feature registry exists for.
//
// A permission's gating feature is a bare string. Misspell one in a catalogue
// and it gates against an entitlement no company can ever hold, so the
// permission is permanently dead — HasPermission requires the feature to be
// present in the company's list, and nothing will ever put it there. No error
// is raised anywhere: the key simply never matches, for everyone, forever.
//
// FeaturesFor() cannot catch this, because it derives the feature list from the
// same catalogue and so always agrees with it. The registry is written
// independently; this test is the comparison.
func TestEveryGateIsSellable(t *testing.T) {
	for _, product := range []authctx.Product{authctx.ProductTMS, authctx.ProductFMS} {
		for key, spec := range authctx.CatalogFor(product) {
			if spec.Feature == "" {
				continue // ungated: available to any company with the product
			}
			if !authctx.IsSellableFeature(product, spec.Feature) {
				t.Errorf("%s: %q gates on %q, which no company can be granted — "+
					"the permission can never match. Add it to the registry, or "+
					"fix the spelling in the catalogue.",
					product, key, spec.Feature)
			}
		}
	}
}

// TestCatalogKeysAreSelfConsistent checks each entry's Key field against the
// map key it is filed under.
//
// They are written twice, so they can disagree. FeatureFor and HasPermission
// look up by map key and would keep working; anything reading spec.Key — an
// administration screen listing what can be granted, or a grant validated
// against the catalogue — would show or accept the other one.
func TestCatalogKeysAreSelfConsistent(t *testing.T) {
	for _, product := range []authctx.Product{authctx.ProductTMS, authctx.ProductFMS} {
		for key, spec := range authctx.CatalogFor(product) {
			if spec.Key != key {
				t.Errorf("%s: entry filed under %q declares Key %q", product, key, spec.Key)
			}
			if _, _, ok := strings.Cut(key, "."); !ok {
				t.Errorf("%s: %q is not in subject.action form, so RequireModule "+
					"cannot split it and the route would 500", product, key)
			}
			if spec.Label == "" {
				t.Errorf("%s: %q has no label, so an administration screen has "+
					"nothing to show for it", product, key)
			}
		}
	}
}

// TestDefaultTMSFeaturesAreSellable makes sure a newly registered company is
// granted entitlements that actually exist.
//
// Registration calls GrantDefaults with this list. A name here that is not in
// the registry would write a company_modules row gating nothing, and the
// company would silently lack the module it was supposed to start with.
func TestDefaultTMSFeaturesAreSellable(t *testing.T) {
	defaults := authctx.DefaultTMSFeatures()
	if len(defaults) == 0 {
		t.Fatal("a new company would be granted no entitlement at all")
	}
	for _, name := range defaults {
		if !authctx.IsSellableFeature(authctx.ProductTMS, name) {
			t.Errorf("registration grants %q, which is not a sellable TMS feature", name)
		}
	}
}

// TestSharedFeaturesResolveInBothProducts pins the rule that makes accounting
// and telemetry work.
//
// They belong to neither product. BuildAccess folds shared entitlements into
// every product's feature list, so a TMS permission gated by `accounting`
// resolves for a company that holds it. If they stopped resolving in both, the
// TMS accounting permissions would go dead without anything failing.
func TestSharedFeaturesResolveInBothProducts(t *testing.T) {
	for _, name := range []string{"accounting", "telemetry"} {
		if !authctx.IsSellableFeature(authctx.ProductTMS, name) {
			t.Errorf("%q must resolve in TMS: the TMS catalogue gates on it", name)
		}
		if !authctx.IsSellableFeature(authctx.ProductFMS, name) {
			t.Errorf("%q must resolve in FMS too, or the two products could "+
				"disagree about whether a company holds it", name)
		}
	}
}

// TestFMSMirrorMatchesUpstream compares the vendored FMS registry against the
// artifact FMS publishes.
//
// The FMS half of the feature registry is a copy of a list another team owns.
// A copy drifts: rename a feature there and a token minted here goes on
// describing an entitlement that no longer exists, and every FMS permission
// gated by it starts failing for reasons that point at the wrong repository.
//
// The authority is fms-features.json at the root of the FMS module, which is a
// generated `json.MarshalIndent(features.Registry)` — derived from their Go
// source by `go generate`, never hand-edited. Comparing against the artifact
// rather than parsing their source means this test does not break every time
// they reformat a literal, and it is the same file a CI step can fetch.
//
// The check is skipped rather than failed when FMS is not checked out, because
// a TMS developer with no reason to have that repository should not be blocked
// by its absence. That makes this a local safety net, not a guarantee. Closing
// that gap needs the artifact fetched in CI rather than read from a sibling
// directory.
func TestFMSMirrorMatchesUpstream(t *testing.T) {
	const upstream = "/Users/nathanaeltimothy/Work/Karlo/FMS/fms-backend/fms-features.json"

	raw, err := os.ReadFile(upstream)
	if err != nil {
		t.Skipf("FMS repository not present, cannot check the mirror for drift: %v", err)
	}

	var published []struct {
		Key    string `json:"key"`
		Label  string `json:"label"`
		Parent string `json:"parent"`
		Dev    bool   `json:"dev"`
	}
	if err := json.Unmarshal(raw, &published); err != nil {
		t.Fatalf("the published FMS registry is not valid JSON: %v", err)
	}
	if len(published) == 0 {
		t.Fatal("the published FMS registry is empty, which would make this test " +
			"pass while checking nothing")
	}

	mirrored := map[string]authctx.Feature{}
	for _, f := range authctx.FMSRegistry() {
		mirrored[f.Name] = f
	}

	for _, want := range published {
		got, ok := mirrored[want.Key]
		if !ok {
			t.Errorf("FMS declares feature %q and the mirror does not have it; "+
				"copy fms-features.json into internal/platform/authctx/", want.Key)
			continue
		}
		if got.Description != want.Label {
			t.Errorf("feature %q: FMS labels it %q, the mirror says %q",
				want.Key, want.Label, got.Description)
		}
		// Parent is presentation only on both sides — granting a parent does
		// not grant its children — but it drives how an administration screen
		// groups the list, so a silent change would reshape that screen.
		if got.Parent != want.Parent {
			t.Errorf("feature %q: FMS nests it under %q, the mirror says %q",
				want.Key, want.Parent, got.Parent)
		}
		// Roadmap decides sellability here. A stub that quietly became live,
		// or the reverse, changes what a Karlo admin may grant.
		if got.Roadmap != want.Dev {
			t.Errorf("feature %q: FMS marks dev=%v, the mirror says %v",
				want.Key, want.Dev, got.Roadmap)
		}
	}

	declared := map[string]bool{}
	for _, f := range published {
		declared[f.Key] = true
	}
	for key := range mirrored {
		if !declared[key] {
			t.Errorf("the mirror carries feature %q which FMS no longer declares; "+
				"a token minted here would describe an entitlement that does not exist", key)
		}
	}
}

// TestEveryPermissionIsGated is the check that runs at startup, run again here
// so a bad key fails in CI rather than at deploy.
//
// An ungated permission skips the entitlement check entirely: it works for
// everyone whose role grants it, regardless of what their company bought. That
// used to be expressible by simply omitting the Feature field, which made
// "deliberately ungated" and "nobody filled it in" identical — and the second
// silently granted access nobody decided to give.
func TestEveryPermissionIsGated(t *testing.T) {
	if err := authctx.ValidateCatalogs(); err != nil {
		t.Fatalf("the permission catalogue is invalid:\n%v", err)
	}
}

// TestAdministrationIsGatedButGrantedByDefault covers the tension in gating
// administration at all.
//
// If managing your own members required an entitlement, a company whose
// subscription lapsed would lose the ability to administer itself — including
// the ability to fix the lapse. Granting the feature to every company by
// default resolves it: the check is uniform, and nothing is restricted that was
// not restricted before. Karlo can still withdraw it, but only on purpose.
func TestAdministrationIsGatedButGrantedByDefault(t *testing.T) {
	spec, ok := authctx.CatalogFor(authctx.ProductTMS)["collaboration.inviteMember"]
	if !ok {
		t.Fatal("collaboration.inviteMember is missing from the TMS catalogue")
	}
	if spec.Feature == "" {
		t.Fatal("collaboration.inviteMember must be gated like everything else")
	}

	defaults := authctx.DefaultTMSFeatures()
	if !slices.Contains(defaults, spec.Feature) {
		t.Errorf("%q gates administration, so it must be granted to every company "+
			"by default — otherwise a lapsed entitlement locks a company out of "+
			"managing itself, including out of fixing the lapse", spec.Feature)
	}
}
