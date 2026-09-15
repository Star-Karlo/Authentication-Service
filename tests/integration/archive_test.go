//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/karlo/authentication-service/internal/archive"
)

type memStore struct{ objects map[string][]byte }

func (m *memStore) PutCold(_ context.Context, key string, body []byte) (string, error) {
	m.objects[key] = body
	return "DEEP_ARCHIVE", nil
}

// TestArchiveMovesOldAuditRowsAndPurgesSessions: audit rows past the window
// leave as one Parquet file per day and are deleted; recent rows stay;
// dead sessions go, live ones stay.
func TestArchiveMovesOldAuditRowsAndPurgesSessions(t *testing.T) {
	db := testDB(t)
	resetTables(t, db)
	db.Exec("TRUNCATE TABLE auth_audit_log, sessions")

	company := seedCompany(t, db)
	user := seedUser(t, db, company.ID, "archive@example.com")

	now := time.Now().UTC()
	old1 := now.Add(-45 * 24 * time.Hour)
	old2 := now.Add(-40 * 24 * time.Hour)
	for _, at := range []time.Time{old1, old1.Add(time.Hour), old2, now.Add(-time.Hour)} {
		if err := db.Exec(`INSERT INTO auth_audit_log (user_id, event, succeeded, created_at) VALUES (?, 'login', true, ?)`, user.ID, at).Error; err != nil {
			t.Fatalf("seed audit: %v", err)
		}
	}
	// One dead session, one live.
	for _, exp := range []time.Time{now.Add(-60 * 24 * time.Hour), now.Add(24 * time.Hour)} {
		if err := db.Exec(`INSERT INTO sessions (user_id, token_id, expires_at) VALUES (?, ?, ?)`, user.ID, uuid.New(), exp).Error; err != nil {
			t.Fatalf("seed session: %v", err)
		}
	}

	store := &memStore{objects: map[string][]byte{}}
	sum, err := archive.New(db, store, archive.Options{
		AuditRetain: 30 * 24 * time.Hour, SessionRetain: 30 * 24 * time.Hour, Prefix: "archive/auth",
	}).Run(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if sum.AuditRows != 3 || sum.AuditFiles != 2 || sum.SessionsDeleted != 1 {
		t.Fatalf("summary %+v", sum)
	}
	for k := range store.objects {
		if !strings.HasPrefix(k, "archive/auth/auth_audit_log/dt=") || !strings.HasSuffix(k, ".parquet") {
			t.Fatalf("key layout: %s", k)
		}
	}
	var n int64
	db.Table("auth_audit_log").Count(&n)
	if n != 1 {
		t.Fatalf("expected only the recent audit row to remain, have %d", n)
	}
	db.Table("sessions").Count(&n)
	if n != 1 {
		t.Fatalf("expected only the live session to remain, have %d", n)
	}
}
