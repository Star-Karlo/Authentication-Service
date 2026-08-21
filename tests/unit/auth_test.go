package unit

import (
	"strings"
	"testing"

	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/services"
)

func TestValidatePasswordStrength(t *testing.T) {
	cases := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"too short", "ab1", true},
		{"letters only", "password", true},
		{"digits only", "12345678", true},
		{"valid", "password1", false},
		{"valid mixed", "Str0ngPassword", false},
		// bcrypt silently ignores bytes past 72, so a longer password would
		// give the user a false sense of strength.
		{"beyond bcrypt limit", strings.Repeat("a1", 40), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := services.ValidatePasswordStrength(tc.password)
			if tc.wantErr && err == nil {
				t.Fatalf("expected an error for %q", tc.password)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.password, err)
			}
		})
	}
}

func TestPermissionAllows(t *testing.T) {
	perm := models.Permission{
		"order":     {"read": true, "create": false},
		"agreement": {"approve": true},
	}

	cases := []struct {
		module, action string
		want           bool
	}{
		{"order", "read", true},
		{"order", "create", false},
		{"order", "delete", false},
		{"agreement", "approve", true},
		{"invoice", "read", false},
	}

	for _, tc := range cases {
		if got := perm.Allows(tc.module, tc.action); got != tc.want {
			t.Errorf("Allows(%q, %q) = %v, want %v", tc.module, tc.action, got, tc.want)
		}
	}

	var nilPerm models.Permission
	if nilPerm.Allows("order", "read") {
		t.Error("a nil permission map must grant nothing")
	}
}

func TestIsRootAccountBypassesPermissions(t *testing.T) {
	// A root account carries no permission map and is unrestricted; this
	// reproduces the legacy rule the split must not change.
	root := &models.User{}
	if !root.IsRootAccount() {
		t.Fatal("a user with no parent must be a root account")
	}

	parentID := models.User{}.ID
	child := &models.User{ParentID: &parentID}
	if child.IsRootAccount() {
		t.Fatal("a user with a parent must not be a root account")
	}
}

func TestSecureCompare(t *testing.T) {
	if !services.SecureCompare("secret", "secret") {
		t.Error("identical values must compare equal")
	}
	if services.SecureCompare("secret", "secreT") {
		t.Error("differing values must not compare equal")
	}
	if services.SecureCompare("secret", "") {
		t.Error("a value must not match the empty string")
	}
}
