//go:build integration

package integration

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/repository"
)

// TestRevokeAllEndsEverySession is the behaviour that makes a password change
// meaningful. A password change that leaves existing sessions alive does not
// actually lock anyone out — which is what the legacy design did, since it
// stored one token string on the user row and never invalidated it.
func TestRevokeAllEndsEverySession(t *testing.T) {
	db := testDB(t)
	resetTables(t, db)

	repo := repository.NewSessionRepository(db)
	company := seedCompany(t, db)
	user := seedUser(t, db, company.ID, "sessions@example.com")
	other := seedUser(t, db, company.ID, "other@example.com")

	// Three devices for our user, one for somebody else.
	var tokenIDs []uuid.UUID
	for i := 0; i < 3; i++ {
		tokenID := uuid.New()
		tokenIDs = append(tokenIDs, tokenID)
		if err := repo.Create(ctx(), &models.Session{
			UserID:    user.ID,
			TokenID:   tokenID,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}); err != nil {
			t.Fatalf("could not create a session: %v", err)
		}
	}

	otherToken := uuid.New()
	if err := repo.Create(ctx(), &models.Session{
		UserID:    other.ID,
		TokenID:   otherToken,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("could not create the other session: %v", err)
	}

	active, err := repo.ListActiveForUser(ctx(), user.ID)
	if err != nil {
		t.Fatalf("could not list sessions: %v", err)
	}
	if len(active) != 3 {
		t.Fatalf("expected 3 active sessions, got %d", len(active))
	}

	revoked, err := repo.RevokeAllForUser(ctx(), user.ID)
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if revoked != 3 {
		t.Errorf("revoked %d sessions, want 3", revoked)
	}

	active, err = repo.ListActiveForUser(ctx(), user.ID)
	if err != nil {
		t.Fatalf("could not list sessions: %v", err)
	}
	if len(active) != 0 {
		t.Errorf("%d sessions survived the revocation", len(active))
	}

	// Another user's session must be untouched.
	otherActive, err := repo.ListActiveForUser(ctx(), other.ID)
	if err != nil {
		t.Fatalf("could not list the other user's sessions: %v", err)
	}
	if len(otherActive) != 1 {
		t.Errorf("revocation reached another user's sessions")
	}

	// Revocation is a timestamp, not a delete: the row survives so the audit
	// trail can still explain why someone was logged out.
	session, err := repo.FindByTokenID(ctx(), tokenIDs[0])
	if err != nil {
		t.Fatalf("a revoked session should still be retrievable: %v", err)
	}
	if session.RevokedAt == nil {
		t.Error("the session was not marked revoked")
	}
	if session.IsActive() {
		t.Error("a revoked session still reports itself active")
	}
}

// TestSingleDeviceEvictionKeepsTheNewestSession covers the legacy tokenKapps
// rule: for shipper, transporter and manager, logging in on a second device
// ends the first.
func TestSingleDeviceEvictionKeepsTheNewestSession(t *testing.T) {
	db := testDB(t)
	resetTables(t, db)

	repo := repository.NewSessionRepository(db)
	company := seedCompany(t, db)
	user := seedUser(t, db, company.ID, "singledevice@example.com")

	first := uuid.New()
	if err := repo.Create(ctx(), &models.Session{
		UserID:       user.ID,
		TokenID:      first,
		SingleDevice: true,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("could not create the first session: %v", err)
	}

	second := uuid.New()
	if err := repo.Create(ctx(), &models.Session{
		UserID:       user.ID,
		TokenID:      second,
		SingleDevice: true,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("could not create the second session: %v", err)
	}

	// The eviction runs after the new session exists, so a failure cannot leave
	// the user with no working session at all.
	if err := repo.RevokeOtherSingleDeviceSessions(ctx(), user.ID, second); err != nil {
		t.Fatalf("eviction failed: %v", err)
	}

	active, err := repo.ListActiveForUser(ctx(), user.ID)
	if err != nil {
		t.Fatalf("could not list sessions: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("expected exactly 1 surviving session, got %d", len(active))
	}
	if active[0].TokenID != second {
		t.Error("the eviction kept the wrong session")
	}
}

// TestExpiredSessionsArePruned covers the cleanup sweep. Revocation is a
// timestamp rather than a delete, so without a sweep the table grows forever.
func TestExpiredSessionsArePruned(t *testing.T) {
	db := testDB(t)
	resetTables(t, db)

	repo := repository.NewSessionRepository(db)
	company := seedCompany(t, db)
	user := seedUser(t, db, company.ID, "pruning@example.com")

	// One long expired, one recently expired, one live.
	for _, expiry := range []time.Duration{-30 * 24 * time.Hour, -time.Hour, 24 * time.Hour} {
		if err := repo.Create(ctx(), &models.Session{
			UserID:    user.ID,
			TokenID:   uuid.New(),
			ExpiresAt: time.Now().Add(expiry),
		}); err != nil {
			t.Fatalf("could not create a session: %v", err)
		}
	}

	// The sweep keeps a grace period, so a session that expired yesterday is
	// still available to explain a "why was I logged out" report.
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	deleted, err := repo.DeleteExpired(ctx(), cutoff)
	if err != nil {
		t.Fatalf("prune failed: %v", err)
	}
	if deleted != 1 {
		t.Errorf("pruned %d sessions, want 1 (only the long-expired one)", deleted)
	}

	var remaining int64
	if err := db.Model(&models.Session{}).Where("user_id = ?", user.ID).Count(&remaining).Error; err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if remaining != 2 {
		t.Errorf("%d sessions remain, want 2", remaining)
	}
}

// TestRefreshTokenLookupUsesTheHash confirms the plaintext refresh token is
// never stored: lookups go through the hash, so a database leak yields no
// usable sessions.
func TestRefreshTokenLookupUsesTheHash(t *testing.T) {
	db := testDB(t)
	resetTables(t, db)

	repo := repository.NewSessionRepository(db)
	company := seedCompany(t, db)
	user := seedUser(t, db, company.ID, "refresh@example.com")

	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tokenID := uuid.New()
	if err := repo.Create(ctx(), &models.Session{
		UserID:           user.ID,
		TokenID:          tokenID,
		RefreshTokenHash: strptr(hash),
		ExpiresAt:        time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("could not create the session: %v", err)
	}

	found, err := repo.FindByRefreshHash(ctx(), hash)
	if err != nil {
		t.Fatalf("lookup by hash failed: %v", err)
	}
	if found.TokenID != tokenID {
		t.Error("the wrong session was resolved")
	}

	if _, err := repo.FindByRefreshHash(ctx(), "not-a-real-hash"); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("an unknown hash should return ErrNotFound, got %v", err)
	}
}
