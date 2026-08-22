package authctx

import "slices"

// ProductAccess is one person's access to one product.
//
// Absent entirely means no access to that product at all — which is the common
// case, not an edge one. A TMS driver has a tms entry and no fms entry; an
// FMS-only customer has the reverse.
type ProductAccess struct {
	// Role is the tenant role in that product's own vocabulary. TMS uses job
	// personas (shipper, transporter, driver); FMS uses privilege tiers
	// (operator, manager, admin). Neither vocabulary has to accommodate the
	// other, which is why this is per product.
	Role string `json:"role"`

	// Permissions are the granted keys from the product's catalogue. A flat
	// list rather than a nested map: it is the shape FMS already uses in
	// production, and the nested form carried no information this does not.
	Permissions []string `json:"perms,omitempty"`

	// Features is the COMPANY's entitlement for this product. The user's
	// permissions can only ever narrow it.
	Features []string `json:"feats,omitempty"`
}

// HasPermission reports whether a principal may perform an action in a product.
//
// Three conditions, and all three must hold:
//
//  1. The person has access to the product at all.
//  2. The permission is granted to them.
//  3. The company holds the entitlement that gates it — where the gate is read
//     from the catalogue, NOT derived from the key. `fuel.view` is gated by
//     `live`; splitting the key on its dot would gate it against a `fuel`
//     feature that does not exist and deny everyone.
//
// A permission with no gate needs only the first two: master data and
// administration are available to any company that has the product.
func (p Principal) HasPermission(product Product, key string) bool {
	// Karlo staff administer across tenants and are not subject to any one
	// company's entitlement.
	if p.IsPlatformStaff {
		return true
	}

	access, ok := p.Access[product]
	if !ok {
		return false
	}

	if !slices.Contains(access.Permissions, key) {
		return false
	}

	feature, known := FeatureFor(product, key)
	if !known {
		// A key nobody declares grants nothing. This is what stops a stale
		// permission — left behind by a renamed feature — from quietly
		// continuing to work.
		return false
	}
	if feature == "" {
		return true
	}

	return slices.Contains(access.Features, feature)
}

// HasProduct reports whether the principal may use a product at all.
//
// Use it to decide whether to show a product in a switcher.
func (p Principal) HasProduct(product Product) bool {
	if p.IsPlatformStaff {
		return true
	}
	_, ok := p.Access[product]
	return ok
}

// RoleIn returns the principal's role in a product, or empty if they have none.
func (p Principal) RoleIn(product Product) string {
	return p.Access[product].Role
}

// CompanyHasFeature reports whether the company holds an entitlement,
// regardless of what this user is permitted.
//
// Use this to decide what to SHOW — a navigation menu, or the set of
// permissions an administrator may assign. Use HasPermission to decide what to
// ALLOW.
func (p Principal) CompanyHasFeature(product Product, feature string) bool {
	if p.IsPlatformStaff {
		return true
	}
	return slices.Contains(p.Access[product].Features, feature)
}

// GrantablePermissions returns what an administrator of this company may assign
// to a colleague in a product.
//
// This is the catalogue narrowed to the company's entitlement, which is why a
// company without accounting sees no accounting section in the permission
// editor rather than one that appears to work and then does nothing.
func (p Principal) GrantablePermissions(product Product) []PermissionSpec {
	catalog := CatalogFor(product)

	var held []string
	if p.IsPlatformStaff {
		held = FeaturesFor(product)
	} else {
		access, ok := p.Access[product]
		if !ok {
			return nil
		}
		held = access.Features
	}

	out := make([]PermissionSpec, 0, len(catalog))
	for _, spec := range catalog {
		// Ungated permissions are always assignable.
		if spec.Feature == "" || slices.Contains(held, spec.Feature) {
			out = append(out, spec)
		}
	}
	return out
}
