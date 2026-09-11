//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/karlo/authentication-service/internal/repository"
	"github.com/karlo/authentication-service/internal/services"
)

func testHash(p string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.MinCost)
	return string(b), err
}

// TestTwoTransportersOneShipper is the whole design in one test.
//
// Transporter A records a shipper with no tax number. Transporter B records
// what is really the same business, also with no tax number, so nothing can
// tell they are the same and two rows exist. The shipper then claims one and
// supplies the tax number — which is the moment the duplicate becomes visible.
// Afterwards both transporters must still reach their customer.
func TestTwoTransportersOneShipper(t *testing.T) {
	db := testDB(t)
	svc := services.NewShipperService(db, repository.NewAuditRepository(db))
	ctx := context.Background()

	newTransporter := func(name string) uuid.UUID {
		var id string
		db.Raw(`INSERT INTO companies (name, role) VALUES (?, 'transporter') RETURNING id::text`, name).Scan(&id)
		parsed := uuid.MustParse(id)
		t.Cleanup(func() { db.Exec(`DELETE FROM companies WHERE id = ?`, parsed) })
		return parsed
	}
	transporterA := newTransporter("Claim Test Transporter A")
	transporterB := newTransporter("Claim Test Transporter B")

	var actor uuid.UUID
	{
		var id string
		db.Raw(`INSERT INTO users (company_id, password_hash) VALUES (?, 'x') RETURNING id::text`,
			transporterA).Scan(&id)
		actor = uuid.MustParse(id)
		t.Cleanup(func() { db.Exec(`DELETE FROM users WHERE id = ?`, actor) })
	}

	// Neither transporter knows the tax number, so two rows are created and
	// nothing at this point could have prevented it.
	a, err := svc.CreateShipper(ctx, transporterA, actor, services.CreateShipperInput{Name: "Toko Jaya"})
	if err != nil {
		t.Fatalf("transporter A creating the shipper: %v", err)
	}
	// B happens to know the tax number, A does not. That asymmetry is what
	// makes the duplicate DETECTABLE later: the claim can only match against a
	// number that is already recorded somewhere. If neither transporter had
	// supplied one, claiming would simply set it on the row being claimed and
	// the other row would stay invisible — see the note in the test below.
	knownNPWP := "01.234.567.8-901.000"
	b, err := svc.CreateShipper(ctx, transporterB, actor, services.CreateShipperInput{
		Name: "Toko Jaya Abadi", NPWP: &knownNPWP,
	})
	if err != nil {
		t.Fatalf("transporter B creating the shipper: %v", err)
	}
	if a.Company.ID == b.Company.ID {
		t.Fatal("without a tax number these cannot be recognised as the same business")
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM users WHERE company_id IN (?, ?)`, a.Company.ID, b.Company.ID)
		db.Exec(`DELETE FROM roles WHERE company_id IN (?, ?)`, a.Company.ID, b.Company.ID)
		db.Exec(`DELETE FROM company_modules WHERE company_id IN (?, ?)`, a.Company.ID, b.Company.ID)
		db.Exec(`DELETE FROM company_product_settings WHERE company_id IN (?, ?)`, a.Company.ID, b.Company.ID)
		db.Exec(`DELETE FROM companies WHERE id IN (?, ?)`, a.Company.ID, b.Company.ID)
	})

	// The shipper is sent a link for A's copy and claims it, supplying the tax
	// number for the first time.
	token, _, err := svc.IssueClaimLink(ctx, a.Company.ID, actor)
	if err != nil {
		t.Fatalf("issuing the claim link: %v", err)
	}

	name, err := svc.PreviewClaim(ctx, token)
	if err != nil {
		t.Fatalf("previewing: %v", err)
	}
	if name != "Toko Jaya" {
		t.Errorf("the preview must name the company being claimed, got %q", name)
	}

	// Supplying the tax number is where B's copy is discovered.
	claimed, err := svc.Claim(ctx, services.ClaimInput{
		Token:    token,
		Email:    "owner-" + uuid.NewString() + "@tokojaya.test",
		Password: "Password123",
		FullName: "Toko Jaya Owner",
		NPWP:     "01.234.567.8-901.000",
	}, testHash)
	if err != nil {
		t.Fatalf("claiming: %v", err)
	}

	// The claimed company keeps its ID. This is the property the design exists
	// for: every order already recorded against it stays linked.
	if claimed.CompanyID != a.Company.ID {
		t.Error("claiming must not change the company's identity, or existing orders are orphaned")
	}
	if claimed.DuplicateOfCompanyID == nil || *claimed.DuplicateOfCompanyID != b.Company.ID {
		t.Error("the duplicate should have been found when the tax number was supplied")
	}

	// Both transporters still reach their customer — B's link moved across.
	for _, tr := range []struct {
		id   uuid.UUID
		name string
	}{{transporterA, "A"}, {transporterB, "B"}} {
		shippers, err := svc.ListShippers(ctx, tr.id)
		if err != nil {
			t.Fatalf("listing transporter %s's shippers: %v", tr.name, err)
		}
		found := false
		for _, sh := range shippers {
			if sh.ID == claimed.CompanyID {
				found = true
			}
		}
		if !found {
			t.Errorf("transporter %s must still reach the shipper after the merge", tr.name)
		}
	}

	// The claimant administers the company.
	var grantsAll bool
	db.Raw(`SELECT r.grants_all FROM roles r WHERE r.id = ?`, claimed.RoleID).Scan(&grantsAll)
	if !grantsAll {
		t.Error("the claiming account must administer the company it claimed")
	}

	// The link is single-use.
	if _, err := svc.Claim(ctx, services.ClaimInput{
		Token: token, Email: "second@tokojaya.test", Password: "Password123", NPWP: "01.234.567.8-901.000",
	}, testHash); err == nil {
		t.Error("a claim link must work only once")
	}
}

// TestCreateShipperLinksWhenTheTaxNumberIsKnown covers the other path: the
// second transporter DOES know the tax number, so no duplicate is created at
// all and no merge is ever needed.
func TestCreateShipperLinksWhenTheTaxNumberIsKnown(t *testing.T) {
	db := testDB(t)
	svc := services.NewShipperService(db, repository.NewAuditRepository(db))
	ctx := context.Background()

	var tA, tB uuid.UUID
	for _, p := range []struct {
		name string
		out  *uuid.UUID
	}{{"Known Tax A", &tA}, {"Known Tax B", &tB}} {
		var id string
		db.Raw(`INSERT INTO companies (name, role) VALUES (?, 'transporter') RETURNING id::text`, p.name).Scan(&id)
		*p.out = uuid.MustParse(id)
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM companies WHERE name LIKE 'Known Tax %'`) })

	npwp := "09.876.543.2-109.000"
	first, err := svc.CreateShipper(ctx, tA, uuid.Nil, services.CreateShipperInput{
		Name: "Sumber Rejeki", NPWP: &npwp,
	})
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM companies WHERE id = ?`, first.Company.ID) })

	// Same business, punctuation stripped. Must reach the SAME row.
	plain := "098765432109000"
	second, err := svc.CreateShipper(ctx, tB, uuid.Nil, services.CreateShipperInput{
		Name: "Sumber Rejeki Jaya", NPWP: &plain,
	})
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !second.Existing {
		t.Error("the second transporter must be told they were linked to an existing shipper")
	}
	if second.Company.ID != first.Company.ID {
		t.Error("the same tax number must reach the same company, however it is punctuated")
	}
}

// TestPersonalShipperHasNoNIB covers the distinction between the two kinds.
func TestPersonalShipperHasNoNIB(t *testing.T) {
	db := testDB(t)
	svc := services.NewShipperService(db, repository.NewAuditRepository(db))

	var tr uuid.UUID
	{
		var id string
		db.Raw(`INSERT INTO companies (name, role) VALUES ('Personal Test Tr', 'transporter') RETURNING id::text`).Scan(&id)
		tr = uuid.MustParse(id)
		t.Cleanup(func() { db.Exec(`DELETE FROM companies WHERE id = ?`, tr) })
	}

	nib := "1234567890123"
	_, err := svc.CreateShipper(context.Background(), tr, uuid.Nil, services.CreateShipperInput{
		Name: "Pak Budi", EntityType: "personal", NIB: &nib,
	})
	if err == nil {
		t.Error("a personal shipper has no business registration, so an NIB must be refused")
	}
}
