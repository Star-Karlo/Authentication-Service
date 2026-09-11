//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/karlo/authentication-service/internal/repository"
	"github.com/karlo/authentication-service/internal/services"
)

// TestMergingDuplicateShippers covers the case the whole design exists for:
// two transporters each created a placeholder for the same real business, and
// it only became visible when one of them supplied a tax number.
func TestMergingDuplicateShippers(t *testing.T) {
	db := testDB(t)
	svc := services.NewMergeService(db, repository.NewAuditRepository(db))
	ctx := context.Background()

	newCompany := func(name string) uuid.UUID {
		var idText string
		err := db.Raw(`INSERT INTO companies (name, role) VALUES (?, 'shipper') RETURNING id::text`,
			name).Scan(&idText).Error
		if err != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
		id, perr := uuid.Parse(idText)
		if perr != nil {
			t.Fatalf("unreadable id: %v", perr)
		}
		t.Cleanup(func() { db.Exec(`DELETE FROM companies WHERE id = ?`, id) })
		return id
	}

	survivor := newCompany("Survivor Logistics")
	duplicate := newCompany("Survivor Logistik") // the same business, typed differently
	transporterA := newCompany("Transporter A")
	transporterB := newCompany("Transporter B")

	// Each transporter dealt with a different copy, which is how the two rows
	// came to exist at all.
	db.Exec(`INSERT INTO company_links (transporter_company_id, shipper_company_id) VALUES (?, ?), (?, ?)`,
		transporterA, survivor, transporterB, duplicate)
	// The duplicate carries a detail the survivor lacks.
	db.Exec(`UPDATE companies SET npwp = '01.234.567.8-901.000', address = 'Jl. Merdeka 1' WHERE id = ?`, duplicate)

	result, err := svc.Merge(ctx, survivor, duplicate, nil)
	if err != nil {
		t.Fatalf("merging failed: %v", err)
	}

	// Both transporters now reach the same shipper.
	var links int64
	db.Raw(`SELECT count(*) FROM company_links WHERE shipper_company_id = ?`, survivor).Scan(&links)
	if links != 2 {
		t.Errorf("both transporters must end up linked to the survivor, got %d", links)
	}
	var orphaned int64
	db.Raw(`SELECT count(*) FROM company_links WHERE shipper_company_id = ?`, duplicate).Scan(&orphaned)
	if orphaned != 0 {
		t.Errorf("no link should still point at the merged company, got %d", orphaned)
	}

	// Details the survivor lacked are carried over rather than discarded.
	var npwp, address *string
	db.Raw(`SELECT npwp, address FROM companies WHERE id = ?`, survivor).Row().Scan(&npwp, &address)
	if npwp == nil || address == nil {
		t.Error("details the survivor lacked must be carried over from the duplicate")
	}

	// The loser is kept and points at the winner. Deleting it would break every
	// order in the business service that references this id.
	var mergedInto *string
	var deletedAt *string
	db.Raw(`SELECT merged_into_company_id::text, deleted_at::text FROM companies WHERE id = ?`,
		duplicate).Row().Scan(&mergedInto, &deletedAt)
	if mergedInto == nil || *mergedInto != survivor.String() {
		t.Error("the merged company must point at the survivor so a stale id still resolves")
	}
	if deletedAt == nil {
		t.Error("the merged company must be soft-deleted so it is not offered again")
	}

	// And a stale id resolves forward.
	resolved, err := svc.Resolve(ctx, duplicate)
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	if resolved != survivor {
		t.Errorf("a stale company id must resolve to the survivor, got %s", resolved)
	}

	if result.LinksMoved != 1 {
		t.Errorf("expected one link to move, got %d", result.LinksMoved)
	}
}

// TestMergeRefusesTheDangerousCases covers what must NOT be allowed.
func TestMergeRefusesTheDangerousCases(t *testing.T) {
	db := testDB(t)
	svc := services.NewMergeService(db, repository.NewAuditRepository(db))
	ctx := context.Background()

	var idText string
	db.Raw(`INSERT INTO companies (name, role) VALUES ('Self Merge', 'shipper') RETURNING id::text`).Scan(&idText)
	id := uuid.MustParse(idText)
	t.Cleanup(func() { db.Exec(`DELETE FROM companies WHERE id = ?`, id) })

	// Merging into itself would write a pointer to itself and make resolution
	// loop forever.
	if _, err := svc.Merge(ctx, id, id, nil); err == nil {
		t.Error("merging a company into itself must be refused")
	}

	// A company that does not exist.
	if _, err := svc.Merge(ctx, id, uuid.New(), nil); err == nil {
		t.Error("merging a company that does not exist must be refused")
	}
}

// TestTaxNumberUniquenessIgnoresFormatting is what makes deduplication work at
// all: the same number typed two ways must collide, or the duplicate is created
// regardless of the constraint.
func TestTaxNumberUniquenessIgnoresFormatting(t *testing.T) {
	db := testDB(t)

	err := db.Exec(`INSERT INTO companies (name, role, npwp) VALUES ('Fmt A', 'shipper', '09.876.543.2-109.000')`).Error
	if err != nil {
		t.Fatalf("first insert: %v", err)
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM companies WHERE name LIKE 'Fmt %'`) })

	err = db.Exec(`INSERT INTO companies (name, role, npwp) VALUES ('Fmt B', 'shipper', '098765432109000')`).Error
	if err == nil {
		t.Error("the same tax number typed without punctuation must be refused as a duplicate")
	}

	// But two shippers with no tax number at all are both allowed — that is
	// what lets a transporter create a placeholder knowing only a name.
	err = db.Exec(`INSERT INTO companies (name, role) VALUES ('Fmt C', 'shipper'), ('Fmt D', 'shipper')`).Error
	if err != nil {
		t.Errorf("two companies without a tax number must both be allowed: %v", err)
	}
}
