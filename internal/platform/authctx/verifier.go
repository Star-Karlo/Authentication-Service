package authctx

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Verifier verifies tokens locally against the authentication service's public
// key. Every service except the authentication service uses this.
type Verifier struct {
	pub *rsa.PublicKey
}

// NewVerifier builds a verifier from a PEM-encoded RSA public key.
func NewVerifier(pemBytes []byte) (*Verifier, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("authctx: empty public key")
	}
	pub, err := jwt.ParseRSAPublicKeyFromPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("authctx: parse public key: %w", err)
	}
	return &Verifier{pub: pub}, nil
}

// NewVerifierFromEnv loads the public key from either JWT_PUBLIC_KEY (inline
// PEM, as delivered by a secrets manager) or JWT_PUBLIC_KEY_FILE (a path).
//
// There is deliberately no default and no fallback: a service that cannot load
// a key must fail to start rather than run with a guessable one.
func NewVerifierFromEnv() (*Verifier, error) {
	if inline := os.Getenv("JWT_PUBLIC_KEY"); inline != "" {
		// Secret stores frequently flatten newlines; restore them.
		return NewVerifier([]byte(strings.ReplaceAll(inline, "\\n", "\n")))
	}
	if path := os.Getenv("JWT_PUBLIC_KEY_FILE"); path != "" {
		b, err := readKeyFile(path)
		if err != nil {
			return nil, err
		}
		return NewVerifier(b)
	}
	return nil, errors.New("authctx: set JWT_PUBLIC_KEY or JWT_PUBLIC_KEY_FILE")
}

// Verify parses and validates a token, returning the principal it asserts.
func (v *Verifier) Verify(token string) (Principal, error) {
	claims, err := ParseClaims(token, func(t *jwt.Token) (interface{}, error) {
		return v.pub, nil
	})
	if err != nil {
		return Principal{}, err
	}
	if claims.Principal.UserID == "" {
		return Principal{}, errors.New("authctx: token has no subject")
	}
	return claims.Principal, nil
}

// VerifyWithIssuedAt is Verify, plus when the token was minted.
//
// The issue time is what makes a per-user or per-company revocation possible
// without listing every session: a cutoff refuses everything issued before it,
// so ending a thousand sessions is one entry rather than a thousand — and a
// fresh login afterwards is unaffected, which is what makes "sign in again" a
// working remedy rather than a lockout.
func (v *Verifier) VerifyWithIssuedAt(token string) (Principal, time.Time, error) {
	claims, err := ParseClaims(token, func(t *jwt.Token) (interface{}, error) {
		return v.pub, nil
	})
	if err != nil {
		return Principal{}, time.Time{}, err
	}
	if claims.Principal.UserID == "" {
		return Principal{}, time.Time{}, errors.New("authctx: token has no subject")
	}

	var issuedAt time.Time
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Time
	}
	return claims.Principal, issuedAt, nil
}

// Signer mints tokens. Only the authentication service constructs one.
type Signer struct {
	priv *rsa.PrivateKey
	kid  string
}

// NewSigner builds a signer from a PEM-encoded RSA private key.
func NewSigner(pemBytes []byte, kid string) (*Signer, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("authctx: empty private key")
	}
	priv, err := jwt.ParseRSAPrivateKeyFromPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("authctx: parse private key: %w", err)
	}
	return &Signer{priv: priv, kid: kid}, nil
}

// NewSignerFromEnv loads the private key from JWT_PRIVATE_KEY or
// JWT_PRIVATE_KEY_FILE. As with the verifier, there is no default.
func NewSignerFromEnv() (*Signer, error) {
	kid := os.Getenv("JWT_KEY_ID")
	if inline := os.Getenv("JWT_PRIVATE_KEY"); inline != "" {
		return NewSigner([]byte(strings.ReplaceAll(inline, "\\n", "\n")), kid)
	}
	if path := os.Getenv("JWT_PRIVATE_KEY_FILE"); path != "" {
		b, err := readKeyFile(path)
		if err != nil {
			return nil, err
		}
		return NewSigner(b, kid)
	}
	return nil, errors.New("authctx: set JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_FILE")
}

// Sign mints a token for the principal with the given claims.
func (s *Signer) Sign(p Principal, registered jwt.RegisteredClaims) (string, error) {
	registered.Issuer = Issuer
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, &Claims{
		Principal:        p,
		RegisteredClaims: registered,
	})
	if s.kid != "" {
		token.Header["kid"] = s.kid
	}
	signed, err := token.SignedString(s.priv)
	if err != nil {
		return "", fmt.Errorf("authctx: sign token: %w", err)
	}
	return signed, nil
}

// Public returns the verifier counterpart, so the authentication service can
// verify its own tokens without loading the key twice.
func (s *Signer) Public() *Verifier {
	return &Verifier{pub: &s.priv.PublicKey}
}

// JWKS is the verification key as a JSON Web Key Set, for consumers that
// would rather fetch the key than be handed a file: a rotation then needs
// no coordinated redeploy of every service that checks our tokens.
func (s *Signer) JWKS() map[string]interface{} {
	pub := &s.priv.PublicKey
	key := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
	if s.kid != "" {
		key["kid"] = s.kid
	}
	return map[string]interface{}{"keys": []interface{}{key}}
}

// PublicPEM is the verification key as PEM, the form NewVerifier reads.
func (s *Signer) PublicPEM() string {
	der, err := x509.MarshalPKIXPublicKey(&s.priv.PublicKey)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// readKeyFile loads a PEM key from disk.
//
// The path comes from this process's own environment (JWT_PUBLIC_KEY_FILE or
// JWT_PRIVATE_KEY_FILE), never from a request or any other untrusted source, so
// a variable path here is the intended behaviour rather than a traversal risk.
// It is cleaned first so that a path assembled from a config template with
// stray separators still resolves to what the operator meant.
//
//nolint:gosec // G304,G703: operator-supplied configuration path, not user input
func readKeyFile(path string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("authctx: read %s: %w", path, err)
	}
	return b, nil
}
