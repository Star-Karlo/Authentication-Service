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
		UserID:    "user-1",
		Role:      "transporter",
		CompanyID: "company-1",
		ParentID:  "parent-1",
		Permission: map[string]map[string]bool{
			"order": {"read": true, "create": false},
		},
		TokenID: "session-1",
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

	if got.UserID != want.UserID || got.Role != want.Role || got.CompanyID != want.CompanyID {
		t.Errorf("principal did not survive the round trip: %+v", got)
	}
	if !got.HasModule("order", "read") || got.HasModule("order", "create") {
		t.Errorf("permission map did not survive: %+v", got.Permission)
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
		Principal: Principal{UserID: "attacker", Role: "superadmin"},
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
		Principal: Principal{UserID: "attacker", Role: "superadmin"},
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

// TestHasModule pins the permission rule the monolith applied and this split
// preserves: a root account is unrestricted, and only sub-accounts carry a map.
func TestHasModule(t *testing.T) {
	root := Principal{Role: "shipper"} // no ParentID
	if !root.HasModule("order", "create") {
		t.Error("a root account should not be restricted by module permissions")
	}
	if !root.HasModule("anything", "at-all") {
		t.Error("a root account should pass any module check")
	}

	child := Principal{
		Role:     "shipper",
		ParentID: "parent-1",
		Permission: map[string]map[string]bool{
			"order": {"read": true},
		},
	}
	if !child.HasModule("order", "read") {
		t.Error("a granted permission should pass")
	}
	if child.HasModule("order", "create") {
		t.Error("an absent action should be refused")
	}
	if child.HasModule("invoice", "read") {
		t.Error("an absent module should be refused")
	}

	// A sub-account with no map at all can do nothing, rather than everything.
	bare := Principal{Role: "shipper", ParentID: "parent-1"}
	if bare.HasModule("order", "read") {
		t.Error("a sub-account with no permission map must be refused")
	}
}

func TestHasRole(t *testing.T) {
	p := Principal{Role: "manager"}

	if !p.HasRole("manager") {
		t.Error("the exact role should match")
	}
	if !p.HasRole("admin", "manager", "driver") {
		t.Error("a role present in the list should match")
	}
	if p.HasRole("admin", "driver") {
		t.Error("an absent role should not match")
	}
	if p.HasRole() {
		t.Error("an empty role list should match nothing")
	}
}

func TestPrincipalContextRoundTrip(t *testing.T) {
	want := Principal{UserID: "user-1", Role: "driver"}

	ctx := WithPrincipal(t.Context(), want)

	got, ok := FromContext(ctx)
	if !ok {
		t.Fatal("the principal was not found in the context")
	}
	if got.UserID != want.UserID || got.Role != want.Role {
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
