package unit

import (
	"strings"
	"testing"

	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/karlo/authentication-service/internal/services"
)

func TestValidatePasswordStrength(t *testing.T) {
	cases := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"too short", "12345", true},
		// A six-digit PIN is what a driver types into K-Trip, and 123456 is
		// the planner's default for a new driver account.
		{"six digits", "123456", false},
		{"digits only", "12345678", false},
		{"letters only", "password", false},
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

// TestAdministratorRoleGrantsEverythingHeld replaces the old root-account test.
//
// "Root" was a property of the ACCOUNT — one privileged user per company. It
// could not express two administrators, none, or one who leaves. Access is a
// property of the ROLE now, and an administrator role grants everything the
// company is entitled to WITHOUT enumerating it, so it stays correct the day
// the company buys another module.
func TestAdministratorRoleGrantsEverythingHeld(t *testing.T) {
	admin := authctx.Principal{
		Access: map[authctx.Product]authctx.ProductAccess{
			authctx.ProductTMS: {
				Role:      "Administrator",
				GrantsAll: true,
				Features:  []string{"order"},
			},
		},
	}
	if !admin.HasPermission(authctx.ProductTMS, "order.read") {
		t.Error("an administrator role must hold a permission its company is entitled to, unlisted")
	}
	// The limit: everything the company BOUGHT, not everything that exists.
	if admin.HasPermission(authctx.ProductTMS, "invoice.read") {
		t.Error("an administrator must not reach a module the company has not bought")
	}

	// The same access without the flag grants nothing, which is what makes the
	// flag meaningful rather than decorative.
	member := authctx.Principal{
		Access: map[authctx.Product]authctx.ProductAccess{
			authctx.ProductTMS: {Role: "Dispatch", Features: []string{"order"}},
		},
	}
	if member.HasPermission(authctx.ProductTMS, "order.read") {
		t.Error("a role with no keys and no GrantsAll must grant nothing")
	}

	// And a role's keys work the ordinary way.
	dispatch := authctx.Principal{
		Access: map[authctx.Product]authctx.ProductAccess{
			authctx.ProductTMS: {
				Role:        "Dispatch",
				Permissions: []string{"order.read"},
				Features:    []string{"order"},
			},
		},
	}
	if !dispatch.HasPermission(authctx.ProductTMS, "order.read") {
		t.Error("a key granted by the role must hold")
	}
	if dispatch.HasPermission(authctx.ProductTMS, "order.cancel") {
		t.Error("a key the role does not grant must not hold")
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
