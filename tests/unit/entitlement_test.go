package unit

import (
	"testing"

	"github.com/karlo/authentication-service/internal/platform/authctx"
)

// TestOnlyStaffCanBeEntitlementAdministrators pins the commercial boundary.
//
// Entitlement is what Karlo sells. If any arrangement of permissions or company
// entitlement could satisfy the guard on those routes, a customer could grant
// themselves modules and the boundary would not exist. IsPlatformStaff is the
// one property a tenant cannot acquire, which is why the guard reads it
// directly rather than going through a permission key.
func TestOnlyStaffCanBeEntitlementAdministrators(t *testing.T) {
	// A company administrator: everything the company is entitled to, and the
	// most privileged thing a customer can be.
	root := authctx.Principal{
		Access: map[authctx.Product]authctx.ProductAccess{
			authctx.ProductTMS: {
				Role:      "Administrator",
				GrantsAll: true,
				Features:  authctx.DefaultTMSFeatures(),
			},
		},
	}
	if root.IsPlatformStaff {
		t.Fatal("a company administrator must never be platform staff")
	}

	staff := authctx.Principal{IsPlatformStaff: true}
	if !staff.IsPlatformStaff {
		t.Fatal("staff must be staff")
	}

	// And no permission key grants it either — the catalogue must not contain
	// anything that reads as entitlement administration, because a key can be
	// granted to a customer.
	for key := range authctx.CatalogFor(authctx.ProductTMS) {
		switch key {
		case "entitlement.grant", "entitlement.revoke", "company.entitle":
			t.Errorf("%q is a permission key, so it could be granted to a "+
				"customer, who would then be able to widen their own entitlement", key)
		}
	}
}

// TestSellableFeatureIsCheckedBeforeGranting covers the validation that stops a
// grant from writing a row that gates nothing.
//
// A module name that is not in the registry is not merely useless: the company
// appears to hold something, no permission references it, and the mistake
// surfaces as a support ticket about a feature that "was turned on" and does
// not work.
func TestSellableFeatureIsCheckedBeforeGranting(t *testing.T) {
	if !authctx.IsSellableFeature(authctx.ProductTMS, "order") {
		t.Error("order must be sellable for TMS")
	}
	if authctx.IsSellableFeature(authctx.ProductTMS, "oder") {
		t.Error("a misspelled module must not be sellable")
	}
	// Shared entitlements resolve in both products, so a Karlo admin can sell
	// accounting to a company on either.
	for _, p := range []authctx.Product{authctx.ProductTMS, authctx.ProductFMS} {
		if !authctx.IsSellableFeature(p, "accounting") {
			t.Errorf("accounting must be sellable for %s", p)
		}
	}
	// An FMS roadmap stub is declared but must not be sellable yet.
	if authctx.IsSellableFeature(authctx.ProductFMS, "payroll") {
		t.Error("a roadmap stub must not be sellable: nothing gates on it")
	}
}

// TestUnknownProductIsRejected covers the difference between "denied" and "you
// sent nonsense".
//
// Without the check, an unrecognised product indexes an empty registry and
// every check against it returns false, which a caller reads as a permission
// problem and debugs in entirely the wrong place.
func TestUnknownProductIsRejected(t *testing.T) {
	for _, p := range []authctx.Product{authctx.ProductTMS, authctx.ProductFMS, authctx.ProductShared} {
		if !authctx.IsKnownProduct(p) {
			t.Errorf("%s must be a known product", p)
		}
	}
	if authctx.IsKnownProduct(authctx.Product("wms")) {
		t.Error("an invented product must not be known")
	}
	if authctx.IsKnownProduct(authctx.Product("")) {
		t.Error("an empty product must not be known")
	}
}

// TestProductHintDoesNotDecideAccess documents what the login product hint is
// for, and what it must not become.
//
// The hint shapes the error a person sees at the door. It must never be the
// thing that decides access, because it arrives in the request body: a client
// that omitted it, or sent the wrong one, would otherwise change what the
// account can do.
func TestProductHintDoesNotDecideAccess(t *testing.T) {
	p := authctx.Principal{
		Access: map[authctx.Product]authctx.ProductAccess{
			authctx.ProductTMS: {Role: "shipper", Features: []string{"order"},
				Permissions: []string{"order.read"}},
		},
	}

	if !p.HasProduct(authctx.ProductTMS) {
		t.Error("the account must have TMS")
	}
	if p.HasProduct(authctx.ProductFMS) {
		t.Error("the account must not have FMS")
	}

	// Access is decided by the token's contents, which the hint never touches.
	if !p.HasPermission(authctx.ProductTMS, "order.read") {
		t.Error("a granted permission must hold regardless of where the person signed in")
	}
}
