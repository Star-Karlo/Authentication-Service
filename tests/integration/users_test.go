//go:build integration

package integration

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/platform/query"
	"github.com/karlo/authentication-service/internal/repository"
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
		Role:         "shipper",
		Permission:   models.Permission{},
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
		Role:         "shipper",
		Permission:   models.Permission{},
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
		Role:         "driver",
		Permission:   models.Permission{},
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
