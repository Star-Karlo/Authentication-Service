package unit

import (
	"testing"
	"time"

	"github.com/karlo/authentication-service/internal/models"
)

func TestStringArrayRoundTrip(t *testing.T) {
	cases := [][]string{
		{},
		{"one"},
		{"one", "two", "three"},
		// Postgres array literals need escaping for quotes and commas.
		{`with "quotes"`, "with,comma", `with\backslash`},
	}

	for _, want := range cases {
		encoded, err := models.StringArray(want).Value()
		if err != nil {
			t.Fatalf("Value() failed for %v: %v", want, err)
		}

		var got models.StringArray
		if err := got.Scan([]byte(encoded.(string))); err != nil {
			t.Fatalf("Scan() failed for %v: %v", encoded, err)
		}

		if len(got) != len(want) {
			t.Fatalf("round trip of %v produced %v", want, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("element %d: got %q, want %q", i, got[i], want[i])
			}
		}
	}
}

func TestSessionIsActive(t *testing.T) {
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)
	now := time.Now()

	if s := (&models.Session{ExpiresAt: future}); !s.IsActive() {
		t.Error("an unexpired, unrevoked session must be active")
	}
	if s := (&models.Session{ExpiresAt: past}); s.IsActive() {
		t.Error("an expired session must not be active")
	}
	if s := (&models.Session{ExpiresAt: future, RevokedAt: &now}); s.IsActive() {
		t.Error("a revoked session must not be active, even before expiry")
	}
}

func TestAPIKeyIsUsable(t *testing.T) {
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)
	now := time.Now()

	if k := (&models.APIKey{IsActive: true}); !k.IsUsable() {
		t.Error("an active key with no expiry must be usable")
	}
	if k := (&models.APIKey{IsActive: true, ExpiresAt: &future}); !k.IsUsable() {
		t.Error("an active, unexpired key must be usable")
	}
	if k := (&models.APIKey{IsActive: true, ExpiresAt: &past}); k.IsUsable() {
		t.Error("an expired key must not be usable")
	}
	if k := (&models.APIKey{IsActive: false}); k.IsUsable() {
		t.Error("an inactive key must not be usable")
	}
	if k := (&models.APIKey{IsActive: true, RevokedAt: &now}); k.IsUsable() {
		t.Error("a revoked key must not be usable")
	}
}

func TestPermissionJSONRoundTrip(t *testing.T) {
	want := models.Permission{"order": {"read": true, "create": false}}

	encoded, err := want.Value()
	if err != nil {
		t.Fatalf("Value() failed: %v", err)
	}

	var got models.Permission
	if err := got.Scan(encoded.([]byte)); err != nil {
		t.Fatalf("Scan() failed: %v", err)
	}

	if !got.Allows("order", "read") || got.Allows("order", "create") {
		t.Errorf("round trip changed the permission map: %v", got)
	}
}
