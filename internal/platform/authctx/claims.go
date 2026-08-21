// Package authctx carries the authenticated principal across HTTP handlers and
// gRPC calls.
//
// Tokens are RS256, not HS256. The authentication service holds the private key
// and is the only party that can mint a token; every other service holds only
// the public key and verifies locally, with no network hop on the hot path and
// no shared secret that a compromised service could use to forge identities.
package authctx

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Issuer is the expected `iss` claim. Verification rejects anything else.
const Issuer = "karlo-authentication-service"

// Principal is the authenticated caller. It is intentionally small: it holds
// what is needed to authorise a request, and nothing that could go stale in a
// way that matters. Anything richer is fetched from the authentication service.
type Principal struct {
	UserID    string `json:"uid"`
	Role      string `json:"role"`
	CompanyID string `json:"cid"`
	// ParentID is set for sub-accounts. Permission checks only bite when a user
	// has a parent, matching the legacy EnsureModule rule.
	ParentID string `json:"pid,omitempty"`
	// Permission is the module -> action -> bool map, embedded in the token so
	// module checks need no round trip. It is re-read from the token on every
	// request, so a permission change takes effect at the next token refresh.
	Permission map[string]map[string]bool `json:"perm,omitempty"`
	// SingleDevice marks sessions bound to one device (the legacy tokenKapps
	// rule). Such tokens require confirmation against the authentication
	// service, because revocation must be immediate.
	SingleDevice bool `json:"sd,omitempty"`
	// TokenID identifies the session, so it can be revoked individually.
	TokenID string `json:"jti,omitempty"`
}

// Claims is the JWT body.
type Claims struct {
	Principal Principal `json:"user"`
	jwt.RegisteredClaims
}

// HasModule reports whether the principal may perform module.action.
//
// The rule reproduces the legacy behaviour deliberately: a main account (no
// parent) is unrestricted, and only sub-accounts carry a permission map. If you
// want to tighten this, do it here, in one place, rather than at call sites.
func (p Principal) HasModule(module, action string) bool {
	if p.ParentID == "" {
		return true
	}
	if p.Permission == nil {
		return false
	}
	actions, ok := p.Permission[module]
	if !ok {
		return false
	}
	return actions[action]
}

// HasRole reports whether the principal holds any of the given roles.
func (p Principal) HasRole(roles ...string) bool {
	for _, r := range roles {
		if p.Role == r {
			return true
		}
	}
	return false
}

type principalKey struct{}

// WithPrincipal returns a context carrying the authenticated caller.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// FromContext returns the authenticated caller, if there is one.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// ErrNoPrincipal is returned when a context has no authenticated caller.
var ErrNoPrincipal = errors.New("authctx: no principal in context")

// MustFromContext returns the caller or an error, for code paths where the
// absence of a principal is a programming mistake rather than a client error.
func MustFromContext(ctx context.Context) (Principal, error) {
	p, ok := FromContext(ctx)
	if !ok {
		return Principal{}, ErrNoPrincipal
	}
	return p, nil
}

// ParseClaims validates a token's structure and signature using key, and
// returns the claims. It pins the signing algorithm: accepting whatever the
// token's own header declares is the classic `alg` confusion vulnerability.
func ParseClaims(token string, keyFunc jwt.Keyfunc) (*Claims, error) {
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(token, claims, keyFunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(Issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("authctx: parse token: %w", err)
	}
	if !parsed.Valid {
		return nil, errors.New("authctx: token invalid")
	}
	return claims, nil
}
