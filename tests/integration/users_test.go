//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/config"
	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/karlo/authentication-service/internal/platform/cache"
	"github.com/karlo/authentication-service/internal/platform/query"
	"github.com/karlo/authentication-service/internal/repository"
	"github.com/karlo/authentication-service/internal/services"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// TestPartialUniqueIndexAllowsReuseAfterSoftDelete is the reason the migration
// uses a partial index rather than a plain unique constraint.
//
// Accounts are soft-deleted so referential history survives. Under a plain
// UNIQUE(email), a deleted user would hold their address forever, and someone
// who closed an account could never re-register with the same email. The index
// is scoped to live rows:
//
//	CREATE UNIQUE INDEX uq_users_email ON users (email)
//	  WHERE deleted_at IS NULL AND email IS NOT NULL;
func TestPartialUniqueIndexAllowsReuseAfterSoftDelete(t *testing.T) {
	db := testDB(t)
	resetTables(t, db)

	repo := repository.NewUserRepository(db)
	company := seedCompany(t, db)

	const email = "reuse@example.com"
	original := seedUser(t, db, company.ID, email)

	// While the account is live the address is taken.
	taken, err := repo.ExistsByEmail(ctx(), email)
	if err != nil {
		t.Fatalf("existence check failed: %v", err)
	}
	if !taken {
		t.Fatal("a live account's email should be reported as taken")
	}

	// A second live account with the same address must be refused.
	duplicate := &models.User{
		CompanyID:    &company.ID,
		Email:        strptr(email),
		PasswordHash: original.PasswordHash,
	}
	if err := repo.Create(ctx(), duplicate); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}

	// After a soft delete the address is free again.
	if err := repo.SoftDelete(ctx(), original.ID); err != nil {
		t.Fatalf("soft delete failed: %v", err)
	}

	taken, err = repo.ExistsByEmail(ctx(), email)
	if err != nil {
		t.Fatalf("existence check failed: %v", err)
	}
	if taken {
		t.Error("a soft-deleted account should not hold its email")
	}

	reregistered := &models.User{
		CompanyID:    &company.ID,
		Email:        strptr(email),
		PasswordHash: original.PasswordHash,
	}
	if err := repo.Create(ctx(), reregistered); err != nil {
		t.Fatalf("re-registration after soft delete failed: %v", err)
	}

	// The original row must still exist, so historic references resolve.
	if _, err := repo.FindByIDIncludingDeleted(ctx(), original.ID); err != nil {
		t.Errorf("the soft-deleted user is no longer retrievable: %v", err)
	}
	if _, err := repo.FindByID(ctx(), original.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("a soft-deleted user should not be found by the default scope, got %v", err)
	}
}

// TestFindByIdentifierMatchesAllThreeColumns covers the single-query login
// lookup. The legacy version tried email, then username, then phone in three
// sequential queries, which leaked through response timing which field matched.
func TestFindByIdentifierMatchesAllThreeColumns(t *testing.T) {
	db := testDB(t)
	resetTables(t, db)

	repo := repository.NewUserRepository(db)
	company := seedCompany(t, db)

	user := &models.User{
		CompanyID:    &company.ID,
		Email:        strptr("person@example.com"),
		Username:     strptr("theperson"),
		Phone:        strptr("628123456789"),
		PasswordHash: "$2a$12$notarealhashbutlongenoughtolooklikeone000000000000000",
	}
	if err := repo.Create(ctx(), user); err != nil {
		t.Fatalf("could not create the user: %v", err)
	}

	for _, identifier := range []string{"person@example.com", "theperson", "628123456789"} {
		got, err := repo.FindByIdentifier(ctx(), identifier)
		if err != nil {
			t.Errorf("identifier %q did not resolve: %v", identifier, err)
			continue
		}
		if got.ID != user.ID {
			t.Errorf("identifier %q resolved to the wrong user", identifier)
		}
	}

	// Email lookup must be case-insensitive; the column is CITEXT.
	if _, err := repo.FindByIdentifier(ctx(), "PERSON@EXAMPLE.COM"); err != nil {
		t.Errorf("email lookup should be case-insensitive: %v", err)
	}

	if _, err := repo.FindByIdentifier(ctx(), "nobody@example.com"); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("an unknown identifier should return ErrNotFound, got %v", err)
	}
}

// TestUpdateFieldsRejectsUnknownRows confirms a partial update on a missing row
// reports it rather than silently succeeding.
func TestUpdateFieldsRejectsUnknownRows(t *testing.T) {
	db := testDB(t)
	resetTables(t, db)

	repo := repository.NewUserRepository(db)

	err := repo.UpdateFields(ctx(), uuid.New(), map[string]interface{}{"full_name": "Ghost"})
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// TestCompanyMemberListingIsScoped confirms one company cannot enumerate
// another's staff.
func TestCompanyMemberListingIsScoped(t *testing.T) {
	db := testDB(t)
	resetTables(t, db)

	repo := repository.NewUserRepository(db)

	ours := seedCompany(t, db)
	theirs := seedCompany(t, db)

	seedUser(t, db, ours.ID, "a@ours.example.com")
	seedUser(t, db, ours.ID, "b@ours.example.com")
	seedUser(t, db, theirs.ID, "c@theirs.example.com")

	members, total, err := repo.ListByCompany(ctx(), ours.ID, nil, query.Params{Page: 0, PageSize: 50})
	if err != nil {
		t.Fatalf("listing failed: %v", err)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	for _, m := range members {
		if m.CompanyID == nil || *m.CompanyID != ours.ID {
			t.Errorf("listing leaked a member of another company")
		}
	}
}

// TestRegisterCreatesAUsableCompany walks the whole registration path and
// checks the four rows it must produce.
//
// Registration writes a company, a user, the starting entitlement and the
// product access row. Each of the last two exists to stop a company that
// authenticates and then reaches nothing, and both were added after the first
// version shipped without them. This asserts all four together, because the
// value of registration is precisely that it leaves an account that can work.
//
// It also covers the case that broke it: a root account is granted access with
// NO permission keys, deliberately, since it is unrestricted within its
// company's entitlement. A nil slice rendered as SQL NULL against a NOT NULL
// column, so creating a company through the API failed at the last of its four
// writes.
func TestRegisterCreatesAUsableCompany(t *testing.T) {
	db := testDB(t)
	svc := userService(t, db)

	email := "register-" + uuid.NewString() + "@example.test"
	user, err := svc.Register(context.Background(), services.RegisterInput{
		Email:       email,
		Password:    "Password123",
		FullName:    "Registration Test",
		CompanyName: "Registration Test Co",
		// Which side of the market the COMPANY trades on. Still required when
		// registering a company, and no longer anything to do with the
		// registering person's own access — that comes from their role.
		Role: "shipper",
	})
	if err != nil {
		t.Fatalf("registering a new company failed: %v", err)
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM users WHERE id = ?`, user.ID)
		if user.CompanyID != nil {
			db.Exec(`DELETE FROM companies WHERE id = ?`, *user.CompanyID)
		}
	})

	if user.CompanyID == nil {
		t.Fatal("a registration with no parent must create a company")
	}
	// The founder of a new tenant administers it, and that is now expressed as
	// a ROLE rather than an account type — which is what allows a company to
	// have two administrators, or none, or one who leaves.
	if user.RoleID == nil {
		t.Fatal("a registered account must hold a role; without one it signs in " +
			"and is refused everywhere, which reads as a permissions bug")
	}
	var role models.Role
	if err := db.First(&role, "id = ?", *user.RoleID).Error; err != nil {
		t.Fatalf("reading the assigned role: %v", err)
	}
	if !role.GrantsAll {
		t.Errorf("the founder of a new tenant must hold an administrator role, got %q", role.Name)
	}
	if !role.IsSystem {
		t.Error("the administrator role must be a system role, so a company cannot delete " +
			"the only role able to administer it")
	}

	var modules int64
	db.Raw(`SELECT count(*) FROM company_modules WHERE company_id = ? AND enabled`,
		*user.CompanyID).Scan(&modules)
	if modules == 0 {
		t.Error("the new company holds no entitlement, so it can reach nothing")
	}

	// The registering account gets NO extra permissions, deliberately: its
	// administrator role already grants everything the company is entitled to,
	// so listing keys alongside it would imply a limit that does not exist.
	var extras int64
	if err := db.Raw(`SELECT count(*) FROM user_product_access WHERE user_id = ?`,
		user.ID).Scan(&extras).Error; err != nil {
		t.Fatalf("reading extra access: %v", err)
	}
	if extras != 0 {
		t.Errorf("an administrator needs no extra permissions, found %d rows", extras)
	}
}

// userService assembles a UserService against the test database.
//
// Only the registration path is exercised, so the cache is a no-op and the
// signing key is generated here rather than loaded — nothing on this path mints
// a token, but NewAuthService reads the public half at construction, so the
// signer cannot simply be nil.
func userService(t *testing.T, db *gorm.DB) *services.UserService {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a signing key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	signer, err := authctx.NewSigner(pemBytes, "test")
	if err != nil {
		t.Fatalf("building a signer: %v", err)
	}

	users := repository.NewUserRepository(db)
	sessions := repository.NewSessionRepository(db)
	modules := repository.NewModuleRepository(db)
	access := repository.NewAccessRepository(db)
	audit := repository.NewAuditRepository(db)

	auth := services.NewAuthService(
		users, sessions,
		repository.NewAPIKeyRepository(db),
		repository.NewDeviceTokenRepository(db),
		modules, access, audit,
		signer, cache.NewNoop(),
		&config.Config{BcryptCost: bcrypt.MinCost},
	)

	return services.NewUserService(users, repository.NewRoleRepository(db),
		repository.NewCompanyRepository(db), modules, access, sessions, audit, auth)
}

// TestSeatLimitIsEnforced covers companies.max_users.
//
// The limit counts ACTIVE accounts: a soft-deleted one frees its seat, a
// suspended one does not. That difference is deliberate — removing somebody
// should free their seat, but a suspension is temporary and the person is
// expected back, so freeing it would let somebody else take it and make their
// return fail.
func TestSeatLimitIsEnforced(t *testing.T) {
	db := testDB(t)
	svc := userService(t, db)
	ctx := context.Background()

	owner, err := svc.Register(ctx, services.RegisterInput{
		Email:       "seats-" + uuid.NewString() + "@example.test",
		Password:    "Password123",
		FullName:    "Seat Owner",
		CompanyName: "Seat Test Co",
		Role:        "shipper",
	})
	if err != nil {
		t.Fatalf("registering the company failed: %v", err)
	}
	companyID := *owner.CompanyID
	t.Cleanup(func() {
		db.Exec(`DELETE FROM users WHERE company_id = ?`, companyID)
		db.Exec(`DELETE FROM roles WHERE company_id = ?`, companyID)
		db.Exec(`DELETE FROM company_modules WHERE company_id = ?`, companyID)
		db.Exec(`DELETE FROM company_product_settings WHERE company_id = ?`, companyID)
		db.Exec(`DELETE FROM companies WHERE id = ?`, companyID)
	})

	// One seat: the owner already holds it.
	if err := db.Exec(`UPDATE companies SET max_users = 1 WHERE id = ?`, companyID).Error; err != nil {
		t.Fatalf("setting the limit: %v", err)
	}

	// Scanned as text and parsed: GORM cannot decode a uuid column straight
	// into uuid.UUID here.
	var roleText string
	if err := db.Raw(`SELECT id::text FROM roles WHERE company_id = ? LIMIT 1`, companyID).
		Scan(&roleText).Error; err != nil {
		t.Fatalf("reading the role: %v", err)
	}
	roleID, perr := uuid.Parse(roleText)
	if perr != nil {
		t.Fatalf("unreadable role id %q: %v", roleText, perr)
	}

	invite := func(email string) error {
		_, err := svc.Register(ctx, services.RegisterInput{
			Email:     email,
			Password:  "Password123",
			FullName:  "Invited",
			CompanyID: &companyID,
			RoleID:    &roleID,
			ParentID:  &owner.ID,
		})
		return err
	}

	if err := invite("over-" + uuid.NewString() + "@example.test"); err == nil {
		t.Error("inviting past the seat limit must be refused")
	}

	// Two seats: the same invitation now succeeds, proving the refusal was the
	// limit and not something else about the request.
	if err := db.Exec(`UPDATE companies SET max_users = 2 WHERE id = ?`, companyID).Error; err != nil {
		t.Fatalf("raising the limit: %v", err)
	}
	second := "second-" + uuid.NewString() + "@example.test"
	if err := invite(second); err != nil {
		t.Fatalf("inviting within the limit failed: %v", err)
	}

	// A soft-deleted account frees its seat.
	if err := db.Exec(`UPDATE users SET deleted_at = NOW() WHERE email = ?`, second).Error; err != nil {
		t.Fatalf("soft-deleting: %v", err)
	}
	if err := invite("replacement-" + uuid.NewString() + "@example.test"); err != nil {
		t.Errorf("a removed account must free its seat, but the replacement was refused: %v", err)
	}

	// Zero means unlimited, not zero seats.
	if err := db.Exec(`UPDATE companies SET max_users = 0 WHERE id = ?`, companyID).Error; err != nil {
		t.Fatalf("clearing the limit: %v", err)
	}
	if err := invite("unlimited-" + uuid.NewString() + "@example.test"); err != nil {
		t.Errorf("max_users = 0 must mean unlimited, not a closed company: %v", err)
	}
}
