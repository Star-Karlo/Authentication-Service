//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/karlo/authentication-service/internal/services"
	"gorm.io/gorm"
)

// extraPermsFixture stands up a client company with a modest module set, a
// member of it, and a Karlo staff account administering from outside.
type extraPermsFixture struct {
	svc      *services.UserService
	clientID uuid.UUID
	staffID  uuid.UUID
	memberID uuid.UUID
}

func newExtraPermsFixture(t *testing.T) *extraPermsFixture {
	t.Helper()
	db := testDB(t)

	clientID := uuid.New()
	exec(t, db, `INSERT INTO companies (id, name, role, created_at, updated_at)
		VALUES (?, 'Client Co', 'transporter', NOW(), NOW())`, clientID)
	for _, m := range []string{"collaboration", "order"} {
		exec(t, db, `INSERT INTO company_modules (company_id, product, module, enabled)
			VALUES (?, 'tms', ?, TRUE)`, clientID, m)
	}

	karloID := uuid.New()
	exec(t, db, `INSERT INTO companies (id, name, role, created_at, updated_at)
		VALUES (?, 'Karlo Platform', 'transporter', NOW(), NOW())`, karloID)

	mkUser := func(companyID uuid.UUID, staff bool, label string) uuid.UUID {
		id := uuid.New()
		tag := uuid.NewString()[:8]
		exec(t, db, `INSERT INTO users
			(id, username, email, full_name, password_hash, company_id, is_platform_staff, created_at, updated_at)
			VALUES (?, ?, ?, ?, 'x', ?, ?, NOW(), NOW())`,
			id, label+"-"+tag, label+"-"+tag+"@example.test", label, companyID, staff)
		return id
	}

	return &extraPermsFixture{
		svc:      userService(t, db),
		clientID: clientID,
		staffID:  mkUser(karloID, true, "staff"),
		memberID: mkUser(clientID, false, "member"),
	}
}

// exec fails the test on a bad insert, so a fixture cannot quietly build
// nothing and leave the assertions below passing against an empty database.
func exec(t *testing.T, db *gorm.DB, q string, args ...interface{}) {
	t.Helper()
	if err := db.Exec(q, args...).Error; err != nil {
		t.Fatalf("fixture: %v", err)
	}
}

// TestExtraPermissionsOfferIsSavable is the invariant the admin screen depends
// on: every key the permission dialog OFFERS must be one the save ACCEPTS.
//
// It did not hold. The dialog filled itself from the caller's token, and a
// Karlo staff principal holds every feature in the catalogue, while the save is
// vetted against the entitlement of the company the member belongs to. A staff
// member editing a client's colleague was shown all 65 TMS keys where the
// client held 15; ticking any of the other 50 refused the entire save, so
// nothing was stored and the dialog reopened empty — read as "the permissions
// do not save".
func TestExtraPermissionsOfferIsSavable(t *testing.T) {
	f := newExtraPermsFixture(t)
	ctx := context.Background()

	// What the dialog now offers: the ADMINISTERED company's grantable set.
	offered, err := f.svc.GrantablePermissions(ctx, f.clientID, authctx.ProductTMS)
	if err != nil {
		t.Fatalf("grantable: %v", err)
	}
	if len(offered) == 0 {
		t.Fatal("the company may grant nothing, so the dialog would have no checkboxes")
	}

	keys := make([]string, 0, len(offered))
	for _, spec := range offered {
		keys = append(keys, spec.Key)
	}

	// Ticking every offered box at once must save, not refuse.
	if err := f.svc.SetProductAccess(ctx, f.staffID, f.memberID, authctx.ProductTMS, "", keys, true); err != nil {
		t.Fatalf("the dialog offered %d keys and the save refused them: %v", len(keys), err)
	}

	rows, err := f.svc.ListProductAccess(ctx, f.staffID, f.memberID)
	if err != nil {
		t.Fatalf("reopening the dialog failed: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one access row, got %d", len(rows))
	}
	if got := len(rows[0].Permissions); got != len(keys) {
		t.Errorf("ticked %d keys, the dialog reopens showing %d", len(keys), got)
	}

	// And the caller's own set must NOT be used as the offer: a staff
	// principal's is wider than any one company's, which is the defect.
	staffOffer := authctx.Principal{IsPlatformStaff: true}.GrantablePermissions(authctx.ProductTMS)
	if len(staffOffer) <= len(offered) {
		t.Skip("staff catalogue no longer exceeds the company's; nothing to guard")
	}
	t.Logf("guarding: a staff principal could offer %d keys where this company holds %d",
		len(staffOffer), len(offered))
}
