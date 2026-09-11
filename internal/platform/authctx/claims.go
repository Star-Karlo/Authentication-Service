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
	UserID string `json:"uid"`

	// CompanyID is the shared IAM's identifier for the tenant.
	CompanyID string `json:"cid"`

	// FMSTenantID is gone. FMS authenticates here now, so there is no separate
	// FMS identity to alias — one company, one id, both products.

	// IsPlatformStaff marks a Karlo employee, who administers across tenants
	// and bypasses company entitlement entirely.
	//
	// Product-neutral by design. FMS calls this platform_admin and TMS called
	// it superadmin/admin, but it is one concept and it is not a tenant role —
	// a Karlo employee is staff across both products, not an administrator of
	// one.
	IsPlatformStaff bool `json:"staff,omitempty"`

	// Access holds this person's access per product. A product absent from the
	// map is a product they cannot use at all, which is the common case rather
	// than an edge one.
	Access map[Product]ProductAccess `json:"acc,omitempty"`

	// Root is gone. Access is a property of the ROLE now — see
	// ProductAccess.GrantsAll — because "one privileged account per company"
	// could not express two administrators, or none, or one who leaves.

	// SingleDevice marks sessions bound to one device (the legacy tokenKapps
	// rule). Such tokens are confirmed against the session store, because
	// revocation must be immediate.
	SingleDevice bool `json:"sd,omitempty"`

	// TokenID identifies the session, so it can be revoked individually.
	TokenID string `json:"jti,omitempty"`
}

// Claims is the JWT body.
type Claims struct {
	Principal Principal `json:"user"`
	jwt.RegisteredClaims
}

// serviceProduct is the product this service belongs to.
//
// Set once at startup by the service's main. It exists so that route guards
// stay `RequirePermission("order.read")` rather than repeating the product at
// thirty call sites — every service is exactly one product, and repeating it
// would be noise that could be got wrong.
var serviceProduct = ProductTMS

// SetProduct declares which product this service belongs to. Call it once,
// before serving.
func SetProduct(p Product) { serviceProduct = p }

// CurrentProduct returns the product this service belongs to.
func CurrentProduct() Product { return serviceProduct }

// HasModule reports whether the principal may perform module.action in this
// service's product.
//
// A convenience over HasPermission for the `module.action` spelling the route
// guards use. The gating entitlement is read from the catalogue, not derived
// from the module name — see PermissionSpec.Feature for why that distinction
// matters.
func (p Principal) HasModule(module, action string) bool {
	return p.HasPermission(serviceProduct, module+"."+action)
}

// Role returns the principal's role in this service's product.
//
// Empty means they have no access to this product at all.
func (p Principal) Role() string {
	return p.RoleIn(serviceProduct)
}

// HasRole reports whether the principal holds any of the given roles in this
// service's product.
func (p Principal) HasRole(roles ...string) bool {
	// Platform staff are not tenant users and hold no tenant role, but they may
	// do anything a tenant role could.
	if p.IsPlatformStaff {
		return true
	}
	role := p.RoleIn(serviceProduct)
	if role == "" {
		return false
	}
	for _, r := range roles {
		if role == r {
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
