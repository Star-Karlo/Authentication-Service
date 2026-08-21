//go:build integration

package integration

import (
	"sort"
	"testing"

	"github.com/karlo/authentication-service/internal/models"
	"gorm.io/gorm"
)

// TestModelColumnsMatchTheSchema compares what GORM will actually write against
// what the migration actually created.
//
// This exists because of a real bug it found: GORM derives a column name from
// the Go field name, and `AcceptedTnCAt` becomes `accepted_tn_c_at` — the
// capital C starts a new word — while the migration declares `accepted_tnc_at`.
// Every user insert failed with a column-does-not-exist error.
//
// No unit test can catch that: the mismatch only exists between the ORM's
// naming convention and the SQL file, and both are individually correct. This
// checks the pair.
func TestModelColumnsMatchTheSchema(t *testing.T) {
	db := testDB(t)

	entities := []struct {
		name  string
		model interface{}
		table string
	}{
		{"Company", &models.Company{}, "companies"},
		{"User", &models.User{}, "users"},
		{"Session", &models.Session{}, "sessions"},
		{"DeviceToken", &models.DeviceToken{}, "device_tokens"},
		{"APIKey", &models.APIKey{}, "api_keys"},
		{"UserDocument", &models.UserDocument{}, "user_documents"},
		{"CollaborationInvite", &models.CollaborationInvite{}, "collaboration_invites"},
		{"AuditEntry", &models.AuditEntry{}, "auth_audit_log"},
	}

	for _, entity := range entities {
		t.Run(entity.name, func(t *testing.T) {
			actual, err := actualColumns(db, entity.table)
			if err != nil {
				t.Fatalf("could not read the schema for %s: %v", entity.table, err)
			}
			if len(actual) == 0 {
				t.Fatalf("table %s has no columns; is the migration applied?", entity.table)
			}

			expected, err := modelColumns(db, entity.model)
			if err != nil {
				t.Fatalf("could not parse the model: %v", err)
			}

			var missing []string
			for _, col := range expected {
				if !actual[col] {
					missing = append(missing, col)
				}
			}

			if len(missing) > 0 {
				sort.Strings(missing)
				t.Errorf("%s writes columns that do not exist in %s: %v\n"+
					"Add an explicit `gorm:\"column:...\"` tag, or fix the migration.",
					entity.name, entity.table, missing)
			}
		})
	}
}

// actualColumns reads the live schema.
func actualColumns(db *gorm.DB, table string) (map[string]bool, error) {
	var names []string
	err := db.Raw(`
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = ?
	`, table).Scan(&names).Error
	if err != nil {
		return nil, err
	}

	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out, nil
}

// modelColumns asks GORM which columns it would use for a model, which is the
// only authority on what it will actually write.
func modelColumns(db *gorm.DB, model interface{}) ([]string, error) {
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(model); err != nil {
		return nil, err
	}

	var out []string
	for _, field := range stmt.Schema.Fields {
		// Skip associations and computed fields: they have no column of their
		// own. GORM marks those with an empty DBName.
		if field.DBName == "" {
			continue
		}
		out = append(out, field.DBName)
	}
	return out, nil
}
