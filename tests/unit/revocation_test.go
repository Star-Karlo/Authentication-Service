package unit

import (
	"testing"
	"time"

	"github.com/karlo/authentication-service/internal/platform/revocation"
)

// TestCutoffRefusesOldTokensButNotNewOnes is the property that makes a
// per-user revocation possible without listing every session.
//
// Storing a CUTOFF rather than a set of session ids means ending a thousand
// sessions is one entry. It also means signing in again works as a remedy: the
// new token is issued after the cutoff, so it is unaffected. Storing session
// ids instead would have neither property.
func TestCutoffRefusesOldTokensButNotNewOnes(t *testing.T) {
	list := revocation.NewList()

	before := time.Now().Add(-time.Minute)
	cutoff := time.Now()
	after := time.Now().Add(time.Minute)

	list.Apply(revocation.Event{
		Kind: revocation.KindUser, ID: "user-1", At: cutoff,
	})

	if !list.Revoked("", "user-1", "", before) {
		t.Error("a token issued before the cutoff must be refused")
	}
	if list.Revoked("", "user-1", "", after) {
		t.Error("a token issued AFTER the cutoff must be accepted — otherwise " +
			"signing in again would not restore access and the account is locked out")
	}
	if list.Revoked("", "user-2", "", before) {
		t.Error("another person's token must be unaffected")
	}
}

// TestSessionRevocationIsExact covers single-device eviction.
//
// Evicting the older login must NOT use a user cutoff: the new session was
// issued moments earlier and would fall on the wrong side of the line, so the
// device that just signed in would evict itself.
func TestSessionRevocationIsExact(t *testing.T) {
	list := revocation.NewList()
	issued := time.Now()

	list.Apply(revocation.Event{
		Kind: revocation.KindSession, ID: "old-session", At: time.Now(),
	})

	if !list.Revoked("old-session", "user-1", "", issued) {
		t.Error("the evicted session must be refused")
	}
	if list.Revoked("new-session", "user-1", "", issued) {
		t.Error("the session that caused the eviction must survive it")
	}
}

// TestCompanyRevocationCoversEveryone covers an entitlement change, which is a
// company-level fact rather than a per-person one.
func TestCompanyRevocationCoversEveryone(t *testing.T) {
	list := revocation.NewList()
	issued := time.Now().Add(-time.Minute)

	list.Apply(revocation.Event{
		Kind: revocation.KindCompany, ID: "company-1", At: time.Now(),
	})

	for _, user := range []string{"user-1", "user-2", "user-3"} {
		if !list.Revoked("", user, "company-1", issued) {
			t.Errorf("%s at the company must be refused", user)
		}
	}
	if list.Revoked("", "user-9", "company-2", issued) {
		t.Error("another company must be unaffected")
	}
}

// TestLaterCutoffWins covers two revocations for one person.
//
// Keeping the earlier one would let a stale announcement narrow a later, wider
// revocation — the account would be un-revoked by a message that arrived out of
// order, which pub/sub does not guarantee against.
func TestLaterCutoffWins(t *testing.T) {
	list := revocation.NewList()
	early := time.Now().Add(-time.Hour)
	late := time.Now()

	list.Apply(revocation.Event{Kind: revocation.KindUser, ID: "u", At: late})
	list.Apply(revocation.Event{Kind: revocation.KindUser, ID: "u", At: early})

	if !list.Revoked("", "u", "", late.Add(-time.Second)) {
		t.Error("the later cutoff must survive an out-of-order earlier one")
	}
}

// TestPruneKeepsOnlyWhatStillMatters covers the list staying small.
//
// An entry older than the longest token lifetime does nothing: a token that old
// is refused on its own expiry. Keeping it would grow the list without bound.
func TestPruneKeepsOnlyWhatStillMatters(t *testing.T) {
	list := revocation.NewList()
	list.Apply(revocation.Event{
		Kind: revocation.KindUser, ID: "stale", At: time.Now().Add(-24 * time.Hour),
	})
	list.Apply(revocation.Event{
		Kind: revocation.KindUser, ID: "fresh", At: time.Now(),
	})

	list.Prune(2 * time.Hour)

	_, users, _ := list.Size()
	if users != 1 {
		t.Errorf("expected only the fresh entry to survive, got %d", users)
	}
	if list.Revoked("", "fresh", "", time.Now().Add(-time.Minute)) == false {
		t.Error("the fresh revocation must still apply")
	}
}

// TestUnconfiguredNeverRevokes documents the deployment with no Redis.
//
// It fails OPEN: a revocation takes effect when the token expires rather than
// at once. The alternative — refusing everything when the store is missing —
// turns a cache outage into a total outage, for at most one token lifetime of
// extra exposure.
func TestUnconfiguredNeverRevokes(t *testing.T) {
	var c revocation.Checker = revocation.NoopChecker{}
	if c.Revoked("any", "any", "any", time.Now().Add(-time.Hour)) {
		t.Error("with no store configured nothing can be revoked, by design")
	}
}

// TestEncodeRoundTrip covers the wire format, since a malformed announcement
// must be rejected rather than silently applied as a zero value.
func TestEncodeRoundTrip(t *testing.T) {
	original := revocation.Event{
		Kind: revocation.KindUser,
		ID:   "user-1",
		At:   time.Now().UTC().Truncate(time.Second),
	}
	b, err := revocation.Encode(original)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := revocation.Decode(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Kind != original.Kind || got.ID != original.ID || !got.At.Equal(original.At) {
		t.Errorf("round trip changed the event: %+v -> %+v", original, got)
	}

	if _, err := revocation.Decode([]byte(`{"kind":"user"}`)); err == nil {
		t.Error("an event with no id must be refused, not applied to everyone")
	}
	if _, err := revocation.Decode([]byte(`not json`)); err == nil {
		t.Error("malformed json must be refused")
	}
}
