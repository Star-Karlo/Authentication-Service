package repository

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// AccessRepository assembles a person's access across products.
type AccessRepository struct{ db *gorm.DB }

func NewAccessRepository(db *gorm.DB) *AccessRepository { return &AccessRepository{db: db} }

// WithTx returns a repository that writes through the given transaction.
func (r *AccessRepository) WithTx(tx *gorm.DB) *AccessRepository {
	if tx == nil {
		return r
	}
	return &AccessRepository{db: tx}
}

// BuildAccess assembles the per-product access map that goes into a token.
//
// Two reads, merged: the user's own rows (which products they may use, in what
// role, with which permissions) and the company's entitlement per product. Both
// are needed because access is their intersection, and both are embedded so
// that no service has to ask again on the request path.
//
// A product the user has no row for is absent from the result — which is how
// "this person only uses FMS" is expressed.
func (r *AccessRepository) BuildAccess(ctx context.Context, userID uuid.UUID, companyID *uuid.UUID) (map[authctx.Product]authctx.ProductAccess, error) {
	// The role first: it carries the job, and may carry everything.
	// Flat, not an embedded accessRole: GORM's Scan into a plain struct does
	// not descend into anonymous fields, and an embedded version silently
	// came back empty — every non-staff token then carried no role at all.
	var role struct {
		Name            string
		GrantsAll       bool
		Permissions     pq.StringArray `gorm:"type:text[]"`
		IsPlatformStaff bool
	}
	err := r.db.WithContext(ctx).
		Table("users u").
		Select("r.name, r.grants_all, r.permissions, u.is_platform_staff").
		Joins("JOIN roles r ON r.id = u.role_id").
		Where("u.id = ?", userID).
		Scan(&role).Error
	if err != nil {
		return nil, fmt.Errorf("repository: load role: %w", err)
	}

	// Karlo staff administer every product across every tenant. Their
	// access is not the intersection of a role and a company's purchases:
	// whichever company row they happen to be attached to — Karlo's own,
	// which buys nothing — must not decide which consoles they can open.
	// The permission check already bypasses for staff; this makes the
	// access map say the same thing, so a client rendering from it agrees.
	if role.IsPlatformStaff {
		return staffAccess(role.Name), nil
	}

	// Then the per-person extras, which only ever ADD.
	var extras []accessExtra
	err = r.db.WithContext(ctx).
		Table("user_product_access").
		Select("product, permissions").
		Where("user_id = ? AND enabled", userID).
		Scan(&extras).Error
	if err != nil {
		return nil, fmt.Errorf("repository: load extra access: %w", err)
	}

	return r.assemble(ctx, accessRole{Name: role.Name, GrantsAll: role.GrantsAll, Permissions: role.Permissions}, extras, companyID)
}

// BuildAccessForRole is BuildAccess for a machine credential: an API key
// that names a role and no person. The role and the company's entitlement
// decide everything; there are no per-person extras, because there is no
// person.
func (r *AccessRepository) BuildAccessForRole(ctx context.Context, roleID uuid.UUID, companyID *uuid.UUID) (map[authctx.Product]authctx.ProductAccess, error) {
	var role accessRole
	err := r.db.WithContext(ctx).
		Table("roles").
		Select("name, grants_all, permissions").
		Where("id = ?", roleID).
		Scan(&role).Error
	if err != nil {
		return nil, fmt.Errorf("repository: load role: %w", err)
	}
	return r.assemble(ctx, role, nil, companyID)
}

// staffAccess is every product, unrestricted, with every sellable feature.
func staffAccess(roleName string) map[authctx.Product]authctx.ProductAccess {
	if roleName == "" {
		roleName = "Platform Staff"
	}
	out := map[authctx.Product]authctx.ProductAccess{}
	for _, product := range []authctx.Product{authctx.ProductTMS, authctx.ProductFMS} {
		features := []string{}
		for _, f := range authctx.SellableFeatures(product) {
			if !f.Roadmap {
				features = append(features, f.Name)
			}
		}
		sort.Strings(features)
		out[product] = authctx.ProductAccess{
			Role:        roleName,
			GrantsAll:   true,
			Permissions: []string{},
			Features:    features,
		}
	}
	return out
}

type accessRole struct {
	Name        string
	GrantsAll   bool
	Permissions pq.StringArray `gorm:"type:text[]"`
}

type accessExtra struct {
	Product     string
	Permissions pq.StringArray `gorm:"type:text[]"`
}

func (r *AccessRepository) assemble(ctx context.Context, role accessRole, extras []accessExtra, companyID *uuid.UUID) (map[authctx.Product]authctx.ProductAccess, error) {
	// Entitlement: what the company actually bought.
	features := map[string][]string{}
	if companyID != nil {
		var err error
		features, err = entitlementFor(ctx, r.db, *companyID)
		if err != nil {
			return nil, err
		}
	}

	// A role's keys are product-qualified — "tms:order.read" — because a role
	// spans products and has no column to say which. Extras are unqualified
	// because their row names the product. Both end up in the same per-product
	// map here.
	perProduct := map[string][]string{}
	for _, key := range role.Permissions {
		product, bare, ok := strings.Cut(key, ":")
		if !ok {
			// An unqualified key on a role cannot be placed. Skipping is the
			// safe direction — granting it to every product would hand someone
			// access to a product nobody meant to give them.
			continue
		}
		perProduct[product] = append(perProduct[product], bare)
	}
	for _, e := range extras {
		perProduct[e.Product] = append(perProduct[e.Product], []string(e.Permissions)...)
	}

	// Which products this person can reach at all: any the company holds, if
	// they have a role. A role with no keys for a product still gives access to
	// nothing there, but the product itself is visible — which is what lets an
	// administrator grant into it.
	products := map[string]bool{}
	for p := range features {
		if p != string(authctx.ProductShared) {
			products[p] = true
		}
	}
	for p := range perProduct {
		products[p] = true
	}

	if len(products) == 0 {
		return nil, nil
	}

	out := make(map[authctx.Product]authctx.ProductAccess, len(products))
	for product := range products {
		out[authctx.Product(product)] = authctx.ProductAccess{
			Role:        role.Name,
			GrantsAll:   role.GrantsAll,
			Permissions: dedupe(perProduct[product]),
			// Shared entitlements — accounting, telemetry — belong to neither
			// product, so they are folded into every product's feature list. A
			// permission gated by one of them then resolves whichever product
			// the caller is in.
			Features: append(append([]string{}, features[product]...),
				features[string(authctx.ProductShared)]...),
		}
	}
	return out, nil
}

// dedupe removes repeats without reordering, so a key granted by both the role
// and an extra appears once.
func dedupe(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// GrantProductAccess gives one person EXTRA permissions in a product, beyond
// what their role already grants.
//
// It does not replace the role and cannot take anything away: effective access
// is the role UNION these. An administrator wanting to remove an ability must
// change the role or move the person to another one, which is the honest place
// for that decision.
func (r *AccessRepository) GrantProductAccess(ctx context.Context, access *models.ProductAccess) error {
	err := r.db.WithContext(ctx).Exec(`
		INSERT INTO user_product_access (user_id, product, permissions, enabled, granted_by_user_id, note)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (user_id, product) DO UPDATE SET
			permissions = EXCLUDED.permissions,
			enabled = EXCLUDED.enabled,
			granted_by_user_id = EXCLUDED.granted_by_user_id,
			note = EXCLUDED.note,
			updated_at = NOW()
	`, access.UserID, access.Product,
		permissionArray(access.Permissions), access.Enabled,
		access.GrantedByUserID, access.Note).Error
	if err != nil {
		return fmt.Errorf("repository: grant product access: %w", err)
	}
	return nil
}

// permissionArray renders a permission list for the TEXT[] column.
//
// A nil slice must become an empty array, not NULL. pq.StringArray(nil) encodes
// as NULL and the column is NOT NULL, so granting access with no explicit keys
// failed outright — which is the common case here, since most people hold only
// what their role gives them and no extras at all.
func permissionArray(keys []string) pq.StringArray {
	if keys == nil {
		return pq.StringArray{}
	}
	return pq.StringArray(keys)
}

// RevokeProductAccess disables a person's access to a product, keeping the row
// so the grant history survives.
func (r *AccessRepository) RevokeProductAccess(ctx context.Context, userID uuid.UUID, product string) error {
	res := r.db.WithContext(ctx).Exec(
		`UPDATE user_product_access SET enabled = FALSE, updated_at = NOW()
		 WHERE user_id = ? AND product = ?`, userID, product)
	if res.Error != nil {
		return fmt.Errorf("repository: revoke product access: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ListForUser returns every product access row a person holds.
func (r *AccessRepository) ListForUser(ctx context.Context, userID uuid.UUID) ([]models.ProductAccess, error) {
	var out []models.ProductAccess
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("product").
		Find(&out).Error
	if err != nil {
		return nil, fmt.Errorf("repository: list product access: %w", err)
	}
	return out, nil
}

// entitlementFor resolves which features a company holds, per product.
//
// It is a package function rather than a method because TWO repositories need
// the answer and they must not disagree: BuildAccess uses it to fill a token,
// and ModuleRepository.ActiveForCompany uses it to tell an administration
// screen what can be granted. When only the first honoured the entitlement
// mode, a tenant converted to opt-out was told it held no modules while its
// tokens carried the full set — the screen and the token describing the same
// company differently.
//
// The subtlety is what an ABSENT row means, and the answer differs by company
// because the two products disagree:
//
//	grant  — absent means DENIED. A module is held only when an enabled row
//	         says so. This is what TMS has always done.
//
//	revoke — absent means ENABLED. A module is held unless a row disables it.
//	         This is what FMS does, and an FMS tenant migrating onto this
//	         schema arrives in this mode so that nothing it could reach
//	         yesterday stops working today.
//
// Reading the mode per (company, product) rather than assuming one is what
// makes the eventual convergence survivable: a tenant is moved deliberately,
// one at a time, and can be moved back.
//
// A company with no settings row is treated as grant — the closed reading —
// because failing shut on missing configuration is the only safe direction for
// a check that decides what a customer has paid for.
func entitlementFor(ctx context.Context, db *gorm.DB, companyID uuid.UUID) (map[string][]string, error) {
	var rows []struct {
		Product string
		Module  string
		Enabled bool
	}
	// Every row, enabled or not: in revoke mode a DISABLED row is the thing
	// that carries the information, so filtering on enabled here would read as
	// "everything is held" for exactly the tenants that had modules withdrawn.
	err := db.WithContext(ctx).
		Table("company_modules").
		Select("product, module, enabled").
		Where("company_id = ?", companyID).
		Where("valid_from IS NULL OR valid_from <= CURRENT_DATE").
		Where("valid_until IS NULL OR valid_until >= CURRENT_DATE").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("repository: load entitlement: %w", err)
	}

	var modes []struct {
		Product         string
		EntitlementMode string
	}
	err = db.WithContext(ctx).
		Table("company_product_settings").
		Select("product, entitlement_mode").
		Where("company_id = ?", companyID).
		Scan(&modes).Error
	if err != nil {
		return nil, fmt.Errorf("repository: load entitlement mode: %w", err)
	}
	mode := make(map[string]string, len(modes))
	for _, m := range modes {
		mode[m.Product] = m.EntitlementMode
	}

	enabled := map[string]map[string]bool{}
	for _, row := range rows {
		if enabled[row.Product] == nil {
			enabled[row.Product] = map[string]bool{}
		}
		enabled[row.Product][row.Module] = row.Enabled
	}

	// Products the company has any statement about: an explicit mode, or at
	// least one row. A product it has never been configured for grants nothing,
	// under either reading.
	products := map[string]bool{}
	for p := range mode {
		products[p] = true
	}
	for p := range enabled {
		products[p] = true
	}

	features := map[string][]string{}
	for product := range products {
		switch mode[product] {
		case models.EntitlementRevoke:
			// Everything sellable, less whatever was explicitly withdrawn.
			for _, f := range authctx.SellableFeatures(authctx.Product(product)) {
				if f.Roadmap {
					// Declared but not built. Nothing gates on it, and handing
					// it out because it was never explicitly withdrawn would
					// grant a module that does not exist.
					continue
				}
				if disabled, stated := enabled[product][f.Name]; stated && !disabled {
					continue
				}
				features[product] = append(features[product], f.Name)
			}
		default:
			// grant, and anything unrecognised: only what was sold.
			for module, on := range enabled[product] {
				if on {
					features[product] = append(features[product], module)
				}
			}
		}
	}

	return features, nil
}
