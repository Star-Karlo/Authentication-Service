//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/karlo/authentication-service/internal/repository"
	"gorm.io/gorm"
)

// TestEntitlementModes covers the single hardest disagreement between the two
// products: what an ABSENT entitlement row means.
//
// TMS reads absence as denied, FMS reads it as enabled, and they therefore fail
// in opposite directions — TMS closed, FMS open. Getting this wrong in either
// direction is severe. Read an FMS tenant as grant and every module it never
// explicitly bought disappears, which for most tenants is everything. Read a
// TMS company as revoke and it silently receives modules nobody sold it.
//
// The behaviour lives in SQL and in how the rows are interpreted together, so
// only a test against a real database can say whether it is right.
func TestEntitlementModes(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	repo := repository.NewAccessRepository(db)

	t.Run("grant means only what was sold", func(t *testing.T) {
		company, user := seedAccessFixture(t, db, models.EntitlementGrant)

		// One module sold, one explicitly withdrawn.
		grantModule(t, db, company, "tms", "order", true)
		grantModule(t, db, company, "tms", "invoice", false)

		access, err := repo.BuildAccess(ctx, user, &company)
		if err != nil {
			t.Fatalf("BuildAccess: %v", err)
		}
		features := access[authctx.ProductTMS].Features

		if !contains(features, "order") {
			t.Error("a module that was sold must be held")
		}
		if contains(features, "invoice") {
			t.Error("a module explicitly disabled must not be held")
		}
		if contains(features, "truck") {
			t.Error("a module with NO row must not be held under grant — " +
				"absence means denied, or a company reaches what nobody sold it")
		}
	})

	t.Run("revoke means everything except what was withdrawn", func(t *testing.T) {
		company, user := seedAccessFixture(t, db, models.EntitlementRevoke)

		// Only a withdrawal is recorded. Under FMS's reading everything else
		// is held, which is how most of its tenants are configured.
		grantModule(t, db, company, "tms", "invoice", false)

		access, err := repo.BuildAccess(ctx, user, &company)
		if err != nil {
			t.Fatalf("BuildAccess: %v", err)
		}
		features := access[authctx.ProductTMS].Features

		if contains(features, "invoice") {
			t.Error("a module explicitly disabled must not be held, even under revoke")
		}
		if !contains(features, "truck") {
			t.Error("a module with no row MUST be held under revoke — this is the " +
				"case that decides whether an FMS tenant survives the migration")
		}
		if !contains(features, "order") {
			t.Error("every sellable module with no row must be held under revoke")
		}
	})

	t.Run("revoke does not hand out roadmap stubs", func(t *testing.T) {
		company, user := seedAccessFixture(t, db, models.EntitlementRevoke)
		if err := db.Exec(`
			INSERT INTO company_product_settings (company_id, product, entitlement_mode)
			VALUES (?, 'fms', 'revoke')
			ON CONFLICT (company_id, product) DO UPDATE SET entitlement_mode = 'revoke'
		`, company).Error; err != nil {
			t.Fatalf("seed fms mode: %v", err)
		}
		if err := db.Exec(`
			INSERT INTO user_product_access (user_id, product, permissions, enabled)
			VALUES (?, 'fms', '{}', TRUE)
			ON CONFLICT (user_id, product) DO NOTHING
		`, user).Error; err != nil {
			t.Fatalf("seed fms access: %v", err)
		}

		access, err := repo.BuildAccess(ctx, user, &company)
		if err != nil {
			t.Fatalf("BuildAccess: %v", err)
		}
		features := access[authctx.ProductFMS].Features

		if !contains(features, "live") {
			t.Error("a live FMS feature must be held under revoke")
		}
		// FMS declares roadmap modules that are not built and carry no
		// permission keys. Handing one out merely because nobody withdrew it
		// would grant a module that does not exist.
		if contains(features, "payroll") {
			t.Error("a roadmap stub must not be granted under revoke")
		}
	})

	t.Run("no settings row fails closed", func(t *testing.T) {
		company, user := seedAccessFixture(t, db, "")
		grantModule(t, db, company, "tms", "order", true)

		access, err := repo.BuildAccess(ctx, user, &company)
		if err != nil {
			t.Fatalf("BuildAccess: %v", err)
		}
		features := access[authctx.ProductTMS].Features

		if !contains(features, "order") {
			t.Error("an explicitly sold module must still be held")
		}
		if contains(features, "truck") {
			t.Error("with no settings row the reading must be grant: missing " +
				"configuration must never widen what a company can reach")
		}
	})
}

// TestNamedRoleBundleIsUnioned covers FMS's per-company named roles.
//
// A bundle must ADD to a person's own keys rather than replace them. The
// reverse would mean that putting somebody in a team silently removed a
// permission they had been granted individually.
func TestNamedRoleBundleIsUnioned(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	company, user := seedAccessFixture(t, db, models.EntitlementGrant)
	grantModule(t, db, company, "tms", "order", true)
	grantModule(t, db, company, "tms", "agreement", true)

	// The role carries the job; the per-user row carries the exception. Keys on
	// a role are product-qualified because a role spans products; keys on the
	// extras row are not, because its product column says which.
	if err := db.Exec(`
		UPDATE roles SET permissions = '{tms:agreement.read}'
		WHERE company_id = ? AND name = 'Fixture'
	`, company).Error; err != nil {
		t.Fatalf("set role permissions: %v", err)
	}
	if err := db.Exec(`
		UPDATE user_product_access SET permissions = '{order.read}'
		WHERE user_id = ? AND product = 'tms'
	`, user).Error; err != nil {
		t.Fatalf("set extras: %v", err)
	}

	access, err := repository.NewAccessRepository(db).BuildAccess(ctx, user, &company)
	if err != nil {
		t.Fatalf("BuildAccess: %v", err)
	}
	perms := access[authctx.ProductTMS].Permissions

	if !contains(perms, "order.read") {
		t.Error("a key granted to the person individually must survive, on top of the role")
	}
	if !contains(perms, "agreement.read") {
		t.Error("a key from the role must be granted")
	}
}

// seedAccessFixture creates a company and a user with TMS access, in the given
// entitlement mode. An empty mode leaves the settings row out entirely, which
// is the "nobody configured this" case.
func seedAccessFixture(t *testing.T, db *gorm.DB, mode string) (uuid.UUID, uuid.UUID) {
	t.Helper()

	companyID := uuid.New()
	if err := db.Exec(`INSERT INTO companies (id, name, role) VALUES (?, ?, 'shipper')`,
		companyID, "Mode Co "+companyID.String()[:8]).Error; err != nil {
		t.Fatalf("seed company: %v", err)
	}

	userID := uuid.New()
	if err := db.Exec(`
		INSERT INTO users (id, company_id, email, password_hash, full_name)
		VALUES (?, ?, ?, 'x', 'Mode User')
	`, userID, companyID, "mode-"+userID.String()+"@example.test").Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// A role, because access is granted by role now and BuildAccess joins on
	// it. Without one the fixture would produce a user who can reach nothing,
	// and every assertion below would pass for the wrong reason.
	if err := db.Exec(`
		INSERT INTO roles (company_id, name, permissions, grants_all, is_system)
		VALUES (?, 'Fixture', '{}'::text[], FALSE, FALSE)
		ON CONFLICT (company_id, name) DO NOTHING
	`, companyID).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if err := db.Exec(`
		UPDATE users SET role_id = (SELECT id FROM roles WHERE company_id = ? AND name = 'Fixture')
		WHERE id = ?
	`, companyID, userID).Error; err != nil {
		t.Fatalf("assign role: %v", err)
	}
	if err := db.Exec(`
		INSERT INTO user_product_access (user_id, product, permissions, enabled)
		VALUES (?, 'tms', '{}', TRUE)
	`, userID).Error; err != nil {
		t.Fatalf("seed access: %v", err)
	}

	// The migration backfills a grant row for every company, so an "unset"
	// fixture has to remove it rather than simply not add one.
	if mode == "" {
		db.Exec(`DELETE FROM company_product_settings WHERE company_id = ?`, companyID)
	} else {
		if err := db.Exec(`
			INSERT INTO company_product_settings (company_id, product, entitlement_mode)
			VALUES (?, 'tms', ?)
			ON CONFLICT (company_id, product) DO UPDATE SET entitlement_mode = EXCLUDED.entitlement_mode
		`, companyID, mode).Error; err != nil {
			t.Fatalf("seed mode: %v", err)
		}
	}

	t.Cleanup(func() {
		db.Exec(`DELETE FROM users WHERE id = ?`, userID)
		db.Exec(`DELETE FROM companies WHERE id = ?`, companyID)
	})

	return companyID, userID
}

func grantModule(t *testing.T, db *gorm.DB, companyID uuid.UUID, product, module string, enabled bool) {
	t.Helper()
	err := db.Exec(`
		INSERT INTO company_modules (company_id, product, module, enabled)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (company_id, product, module) DO UPDATE SET enabled = EXCLUDED.enabled
	`, companyID, product, module, enabled).Error
	if err != nil {
		t.Fatalf("seed module %s: %v", module, err)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// TestAdminScreenAndTokenAgree pins the fix for a bug that would have appeared
// the first time a tenant was converted to opt-out.
//
// Two paths answer "what does this company hold": BuildAccess fills a token,
// and ActiveForCompany tells an administration screen what can be granted. The
// second read company_modules directly and assumed the opt-in reading, so a
// converted tenant was told it held NOTHING while its tokens carried the full
// set — the screen and the token describing one company differently, with no
// error anywhere.
func TestAdminScreenAndTokenAgree(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	for _, mode := range []string{models.EntitlementGrant, models.EntitlementRevoke} {
		t.Run(mode, func(t *testing.T) {
			company, user := seedAccessFixture(t, db, mode)
			grantModule(t, db, company, "tms", "order", true)
			grantModule(t, db, company, "tms", "invoice", false)

			access, err := repository.NewAccessRepository(db).BuildAccess(ctx, user, &company)
			if err != nil {
				t.Fatalf("BuildAccess: %v", err)
			}
			inToken := access[authctx.ProductTMS].Features

			onScreen, err := repository.NewModuleRepository(db).
				ActiveForCompany(ctx, company, authctx.ProductTMS)
			if err != nil {
				t.Fatalf("ActiveForCompany: %v", err)
			}

			for _, f := range inToken {
				if !contains(onScreen, f) {
					t.Errorf("the token carries %q but the administration screen "+
						"does not offer it", f)
				}
			}
			for _, f := range onScreen {
				if !contains(inToken, f) {
					t.Errorf("the administration screen offers %q but the token "+
						"does not carry it", f)
				}
			}
			if len(inToken) == 0 {
				t.Error("the fixture grants a module, so neither answer should be empty")
			}
		})
	}
}
