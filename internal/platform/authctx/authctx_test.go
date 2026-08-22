package authctx

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testKeys generates a throwaway RSA pair and returns the PEM encodings.
func testKeys(t *testing.T) (privPEM, pubPEM []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generate a key: %v", err)
	}

	privPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("could not marshal the public key: %v", err)
	}
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	return privPEM, pubPEM
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	privPEM, pubPEM := testKeys(t)

	signer, err := NewSigner(privPEM, "test-key")
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	verifier, err := NewVerifier(pubPEM)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	want := Principal{
		UserID:      "user-1",
		CompanyID:   "company-1",
		FMSTenantID: 42,
		ParentID:    "parent-1",
		TokenID:     "session-1",
		Access: map[Product]ProductAccess{
			ProductTMS: {
				Role:        "transporter",
				Permissions: []string{"order.read", "truck.read"},
				Features:    []string{"order", "truck"},
			},
			ProductFMS: {
				Role:        "operator",
				Permissions: []string{"live.view", "vehicles.view"},
				Features:    []string{"live"},
			},
		},
	}

	token, err := signer.Sign(want, jwt.RegisteredClaims{
		Subject:   want.UserID,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	got, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if got.UserID != want.UserID || got.CompanyID != want.CompanyID {
		t.Errorf("principal did not survive the round trip: %+v", got)
	}
	// The FMS alias must survive: without it FMS would have to translate the
	// company UUID on every request to set app.current_tenant.
	if got.FMSTenantID != want.FMSTenantID {
		t.Errorf("FMS tenant alias did not survive: %d", got.FMSTenantID)
	}
	if got.RoleIn(ProductTMS) != "transporter" || got.RoleIn(ProductFMS) != "operator" {
		t.Errorf("per-product roles did not survive: %+v", got.Access)
	}
	if !got.HasPermission(ProductTMS, "order.read") || got.HasPermission(ProductTMS, "order.create") {
		t.Errorf("TMS permissions did not survive: %+v", got.Access[ProductTMS])
	}
	if !got.HasPermission(ProductFMS, "live.view") {
		t.Errorf("FMS permissions did not survive: %+v", got.Access[ProductFMS])
	}
}

// TestVerifierRejectsForeignKey is the core guarantee of the split: only the
// authentication service can mint a token, because only it holds the private
// key. A token signed by anything else must not verify.
func TestVerifierRejectsForeignKey(t *testing.T) {
	privA, _ := testKeys(t)
	_, pubB := testKeys(t)

	signer, err := NewSigner(privA, "a")
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	verifier, err := NewVerifier(pubB)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	token, err := signer.Sign(Principal{UserID: "user-1"}, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if _, err := verifier.Verify(token); err == nil {
		t.Fatal("a token signed with a different key must not verify")
	}
}

// TestVerifierRejectsAlgNone is the regression test for the monolith's keyfunc,
// which returned the secret without inspecting the token's declared algorithm.
// That is the classic `alg` confusion vulnerability: an attacker strips the
// signature, sets alg to "none", and is admitted as anyone they like.
func TestVerifierRejectsAlgNone(t *testing.T) {
	_, pubPEM := testKeys(t)
	verifier, err := NewVerifier(pubPEM)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, &Claims{
		Principal: Principal{UserID: "attacker", IsPlatformStaff: true},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	token, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("could not build the unsigned token: %v", err)
	}

	if _, err := verifier.Verify(token); err == nil {
		t.Fatal("an alg=none token was accepted")
	}
}

// TestVerifierRejectsHMACSignedWithPublicKey covers the other half of algorithm
// confusion: signing with HS256 using the public key as the shared secret,
// which succeeds whenever a verifier does not pin the algorithm.
func TestVerifierRejectsHMACSignedWithPublicKey(t *testing.T) {
	_, pubPEM := testKeys(t)
	verifier, err := NewVerifier(pubPEM)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		Principal: Principal{UserID: "attacker", IsPlatformStaff: true},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	token, err := forged.SignedString(pubPEM)
	if err != nil {
		t.Fatalf("could not build the forged token: %v", err)
	}

	if _, err := verifier.Verify(token); err == nil {
		t.Fatal("an HS256 token signed with the public key was accepted")
	}
}

func TestVerifierRejectsExpiredToken(t *testing.T) {
	privPEM, pubPEM := testKeys(t)
	signer, _ := NewSigner(privPEM, "k")
	verifier, _ := NewVerifier(pubPEM)

	token, err := signer.Sign(Principal{UserID: "user-1"}, jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if _, err := verifier.Verify(token); err == nil {
		t.Fatal("an expired token was accepted")
	}
}

// TestVerifierRequiresExpiry: a token with no exp never expires, which turns a
// single leak into permanent access.
func TestVerifierRequiresExpiry(t *testing.T) {
	privPEM, pubPEM := testKeys(t)
	signer, _ := NewSigner(privPEM, "k")
	verifier, _ := NewVerifier(pubPEM)

	token, err := signer.Sign(Principal{UserID: "user-1"}, jwt.RegisteredClaims{
		IssuedAt: jwt.NewNumericDate(time.Now()),
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if _, err := verifier.Verify(token); err == nil {
		t.Fatal("a token with no expiry was accepted")
	}
}

// TestVerifierRejectsForeignIssuer stops a token minted by some other system
// that happens to share the key from being honoured here.
func TestVerifierRejectsForeignIssuer(t *testing.T) {
	privPEM, pubPEM := testKeys(t)

	priv, err := jwt.ParseRSAPrivateKeyFromPEM(privPEM)
	if err != nil {
		t.Fatalf("could not parse the private key: %v", err)
	}
	verifier, _ := NewVerifier(pubPEM)

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, &Claims{
		Principal: Principal{UserID: "user-1"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "some-other-system",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}).SignedString(priv)
	if err != nil {
		t.Fatalf("could not sign: %v", err)
	}

	if _, err := verifier.Verify(token); err == nil {
		t.Fatal("a token from a foreign issuer was accepted")
	}
}

func TestVerifierRejectsMalformedInput(t *testing.T) {
	_, pubPEM := testKeys(t)
	verifier, _ := NewVerifier(pubPEM)

	for _, token := range []string{
		"",
		"nonsense",
		"a.b",
		"a.b.c",
		"....",
		// The monolith admitted any 32-character string as a static token.
		"OzLm6oJRwxmHFRdrd9InZPzazChw3xf2",
	} {
		if _, err := verifier.Verify(token); err == nil {
			t.Errorf("malformed token %q was accepted", token)
		}
	}
}

func TestNewVerifierRejectsBadKeyMaterial(t *testing.T) {
	for _, in := range [][]byte{nil, {}, []byte("not a pem"), []byte("-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----")} {
		if _, err := NewVerifier(in); err == nil {
			t.Errorf("NewVerifier accepted invalid key material %q", string(in))
		}
	}
}

// TestAccessIsThreeConditions pins the model: product access, user permission,
// and company entitlement must ALL hold.
func TestAccessIsThreeConditions(t *testing.T) {
	p := Principal{
		UserID:    "user-1",
		CompanyID: "company-1",
		ParentID:  "parent-1",
		Access: map[Product]ProductAccess{
			ProductTMS: {
				Role:        "shipper",
				Permissions: []string{"order.read", "invoice.read"},
				Features:    []string{"order"}, // invoice NOT entitled
			},
		},
	}

	t.Run("granted and entitled passes", func(t *testing.T) {
		if !p.HasPermission(ProductTMS, "order.read") {
			t.Error("a granted, entitled permission should pass")
		}
	})

	t.Run("granted but not entitled fails", func(t *testing.T) {
		// The company was never sold invoicing. The user's grant is irrelevant.
		// This is what makes withdrawing an entitlement safe: nobody has to
		// audit every user's permissions afterwards.
		if p.HasPermission(ProductTMS, "invoice.read") {
			t.Error("a permission outside the company entitlement granted access")
		}
	})

	t.Run("entitled but not granted fails", func(t *testing.T) {
		if p.HasPermission(ProductTMS, "order.create") {
			t.Error("an ungranted action passed")
		}
	})

	t.Run("no access to the product at all", func(t *testing.T) {
		if p.HasPermission(ProductFMS, "live.view") {
			t.Error("a person with no FMS access reached an FMS permission")
		}
		if p.HasProduct(ProductFMS) {
			t.Error("HasProduct reported access to a product with no entry")
		}
		if !p.HasProduct(ProductTMS) {
			t.Error("HasProduct denied a product the person has")
		}
	})
}

// TestGatingFeatureIsNotDerivedFromTheKey is the property most likely to be got
// wrong by assumption, and the one that would silently deny everyone.
//
// In FMS the gating entitlement is frequently NOT the key's prefix:
// `fuel.view` is gated by `live`, `dashboard.ai` by `ai_dashboard`,
// `dashcams.manage` by `camera`. Code that split the key on its dot would gate
// fuel.view against a "fuel" feature that does not exist.
func TestGatingFeatureIsNotDerivedFromTheKey(t *testing.T) {
	cases := []struct {
		key         string
		wantFeature string
	}{
		{"fuel.view", "live"},
		{"fuel.price_calc", "live"},
		{"dashboard.ai", "ai_dashboard"},
		{"reports.custom", "custom_report"},
		{"reports.ai", "ai_reporting"},
		{"share_link.create", "generate_link"},
		{"dashcams.manage", "camera"},
		// And the cases where it does coincide, so the test would catch a
		// regression that hardcoded the indirection the other way.
		{"live.view", "live"},
		{"geofence.manage", "geofence"},
	}

	for _, tc := range cases {
		got, known := FeatureFor(ProductFMS, tc.key)
		if !known {
			t.Errorf("%q is not in the FMS catalogue", tc.key)
			continue
		}
		if got != tc.wantFeature {
			t.Errorf("%q is gated by %q, want %q", tc.key, got, tc.wantFeature)
		}
	}

	// The behaviour that follows from it: holding `live` grants fuel.view.
	p := Principal{
		ParentID: "parent-1",
		Access: map[Product]ProductAccess{
			ProductFMS: {
				Role:        "operator",
				Permissions: []string{"fuel.view", "dashboard.ai"},
				Features:    []string{"live"}, // has live, NOT ai_dashboard
			},
		},
	}

	if !p.HasPermission(ProductFMS, "fuel.view") {
		t.Error("fuel.view should be granted by the live entitlement")
	}
	if p.HasPermission(ProductFMS, "dashboard.ai") {
		t.Error("dashboard.ai should need the ai_dashboard entitlement, not dashboard")
	}
}

// TestUngatedPermissionsNeedNoEntitlement covers the master-data and
// administration surface, which is available to any company that has the
// product at all.
func TestUngatedPermissionsNeedNoEntitlement(t *testing.T) {
	p := Principal{
		ParentID: "parent-1",
		Access: map[Product]ProductAccess{
			ProductFMS: {
				Role:        "admin",
				Permissions: []string{"vehicles.edit", "users.manage", "camera.view"},
				Features:    nil, // no entitlements at all
			},
		},
	}

	for _, key := range []string{"vehicles.edit", "users.manage"} {
		if !p.HasPermission(ProductFMS, key) {
			t.Errorf("%q is ungated and should not need an entitlement", key)
		}
	}

	// A gated one still fails.
	if p.HasPermission(ProductFMS, "camera.view") {
		t.Error("camera.view is gated and should need the camera entitlement")
	}
}

// TestUnknownPermissionGrantsNothing: a key nobody declares must not work, so a
// permission left behind by a renamed feature stops rather than lingering.
func TestUnknownPermissionGrantsNothing(t *testing.T) {
	p := Principal{
		ParentID: "parent-1",
		Access: map[Product]ProductAccess{
			ProductTMS: {
				Role:        "shipper",
				Permissions: []string{"order.nonsense", "removed.feature"},
				Features:    []string{"order"},
			},
		},
	}

	for _, key := range []string{"order.nonsense", "removed.feature"} {
		if p.HasPermission(ProductTMS, key) {
			t.Errorf("undeclared key %q granted access", key)
		}
	}
}

// TestPlatformStaffAreProductNeutral: a Karlo employee is staff across both
// products, not an administrator of one.
func TestPlatformStaffAreProductNeutral(t *testing.T) {
	staff := Principal{UserID: "karlo-1", IsPlatformStaff: true} // no Access at all

	for _, product := range []Product{ProductTMS, ProductFMS} {
		if !staff.HasProduct(product) {
			t.Errorf("platform staff should reach %s", product)
		}
	}
	if !staff.HasPermission(ProductFMS, "camera.view") {
		t.Error("platform staff should bypass FMS entitlement")
	}
	if !staff.HasPermission(ProductTMS, "accounting.read") {
		t.Error("platform staff should bypass TMS entitlement")
	}
	if len(staff.GrantablePermissions(ProductFMS)) == 0 {
		t.Error("platform staff should be able to grant FMS permissions")
	}
}

// TestGrantablePermissionsIsNarrowedToTheEntitlement is what the permission
// editor renders. A company without a feature must not see its section.
func TestGrantablePermissionsIsNarrowedToTheEntitlement(t *testing.T) {
	p := Principal{
		Access: map[Product]ProductAccess{
			ProductFMS: {
				Role:     "admin",
				Features: []string{"live", "geofence"},
			},
		},
	}

	grantable := map[string]bool{}
	for _, spec := range p.GrantablePermissions(ProductFMS) {
		grantable[spec.Key] = true
	}

	// Entitled, so offered.
	for _, key := range []string{"live.view", "live.history", "fuel.view", "geofence.manage"} {
		if !grantable[key] {
			t.Errorf("%q should be assignable: its feature is held", key)
		}
	}
	// Ungated, so always offered.
	for _, key := range []string{"vehicles.edit", "users.manage"} {
		if !grantable[key] {
			t.Errorf("%q is ungated and should always be assignable", key)
		}
	}
	// Not entitled, so absent entirely.
	for _, key := range []string{"camera.view", "maintenance.manage", "reports.ai"} {
		if grantable[key] {
			t.Errorf("%q should not be assignable: its feature is not held", key)
		}
	}

	// A product the company has no access to offers nothing.
	if len(p.GrantablePermissions(ProductTMS)) != 0 {
		t.Error("a product with no access should offer no grantable permissions")
	}
}

// TestServiceProductScopesTheConvenienceHelpers covers HasModule/Role/HasRole,
// which the thirty route guards use and which resolve against whichever product
// the service declared at startup.
func TestServiceProductScopesTheConvenienceHelpers(t *testing.T) {
	original := CurrentProduct()
	t.Cleanup(func() { SetProduct(original) })

	p := Principal{
		ParentID: "parent-1",
		Access: map[Product]ProductAccess{
			ProductTMS: {Role: "shipper", Permissions: []string{"order.read"}, Features: []string{"order"}},
			ProductFMS: {Role: "operator", Permissions: []string{"live.view"}, Features: []string{"live"}},
		},
	}

	SetProduct(ProductTMS)
	if p.Role() != "shipper" {
		t.Errorf("Role() = %q under TMS, want shipper", p.Role())
	}
	if !p.HasModule("order", "read") {
		t.Error("HasModule should resolve against TMS")
	}
	if p.HasModule("live", "view") {
		t.Error("HasModule under TMS should not see an FMS permission")
	}
	if !p.HasRole("shipper", "transporter") {
		t.Error("HasRole should match the TMS role")
	}

	SetProduct(ProductFMS)
	if p.Role() != "operator" {
		t.Errorf("Role() = %q under FMS, want operator", p.Role())
	}
	if !p.HasModule("live", "view") {
		t.Error("HasModule should resolve against FMS")
	}
	if p.HasModule("order", "read") {
		t.Error("HasModule under FMS should not see a TMS permission")
	}
}

// TestCatalogsAreWellFormed guards the two catalogues against typos.
func TestCatalogsAreWellFormed(t *testing.T) {
	for _, product := range []Product{ProductTMS, ProductFMS} {
		catalog := CatalogFor(product)
		if len(catalog) == 0 {
			t.Fatalf("%s has an empty catalogue", product)
		}

		for key, spec := range catalog {
			if spec.Key != key {
				t.Errorf("%s: entry %q declares Key %q", product, key, spec.Key)
			}
			if spec.Label == "" {
				t.Errorf("%s: %q has no label, so the editor cannot render it", product, key)
			}
			if spec.Group == "" {
				t.Errorf("%s: %q has no group", product, key)
			}
			if !IsKnownPermission(product, key) {
				t.Errorf("%s: %q is in the catalogue but not recognised", product, key)
			}
		}

		if IsKnownPermission(product, "definitely.notreal") {
			t.Errorf("%s recognised an undeclared key", product)
		}
	}

	// The two catalogues share key names that mean different things —
	// dashboard, notifications, reports. That is exactly why permissions are
	// product-qualified, and this asserts the qualification actually separates
	// them.
	if _, ok := CatalogFor(ProductTMS)["live.view"]; ok {
		t.Error("an FMS key leaked into the TMS catalogue")
	}
	if _, ok := CatalogFor(ProductFMS)["order.read"]; ok {
		t.Error("a TMS key leaked into the FMS catalogue")
	}
}

func TestPrincipalContextRoundTrip(t *testing.T) {
	want := Principal{
		UserID: "user-1",
		Access: map[Product]ProductAccess{
			ProductTMS: {Role: "driver"},
		},
	}

	ctx := WithPrincipal(t.Context(), want)

	got, ok := FromContext(ctx)
	if !ok {
		t.Fatal("the principal was not found in the context")
	}
	if got.UserID != want.UserID || got.RoleIn(ProductTMS) != want.RoleIn(ProductTMS) {
		t.Errorf("got %+v, want %+v", got, want)
	}

	if _, ok := FromContext(t.Context()); ok {
		t.Error("an empty context should carry no principal")
	}

	if _, err := MustFromContext(t.Context()); err == nil {
		t.Error("MustFromContext should error on an empty context")
	}
}

func TestOutgoingTokenPropagation(t *testing.T) {
	ctx := WithOutgoingToken(t.Context(), "the-token")

	got, ok := OutgoingToken(ctx)
	if !ok || got != "the-token" {
		t.Errorf("OutgoingToken = %q, %v", got, ok)
	}

	// An empty token must not be reported as present, or an unauthenticated
	// call would carry an empty Authorization header downstream.
	if _, ok := OutgoingToken(WithOutgoingToken(t.Context(), "")); ok {
		t.Error("an empty token should not be reported as present")
	}
	if _, ok := OutgoingToken(t.Context()); ok {
		t.Error("a bare context should carry no outgoing token")
	}
}
