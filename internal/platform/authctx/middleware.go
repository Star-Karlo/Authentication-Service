package authctx

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"
)

// GinContextKey is where the principal is stored on a gin context, for handlers
// that reach for it directly rather than through the request context.
const GinContextKey = "principal"

// RemoteValidator validates tokens this service cannot verify on its own: the
// legacy 32-character static API tokens, and single-device sessions whose
// revocation must be immediate. It is satisfied by the auth service gRPC
// client. Services that do not accept such tokens may pass nil.
type RemoteValidator interface {
	ValidateToken(ctx context.Context, token string) (Principal, error)
}

// RequireAuth authenticates the request and aborts with 401 if it cannot.
//
// The order matters. Local RS256 verification is tried first because it is the
// common case and costs no network call. The remote path is used only for
// tokens local verification cannot settle.
func RequireAuth(v *Verifier, remote RemoteValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := ExtractToken(c)
		if token == "" {
			abort(c, "No token provided.")
			return
		}

		principal, err := v.Verify(token)
		if err == nil && !principal.SingleDevice {
			bind(c, principal)
			return
		}

		// Either the token is not one of ours (a static token), or it is a
		// single-device session that must be confirmed against the session
		// store. Both require the authentication service.
		if remote == nil {
			abort(c, "Silahkan untuk login ulang")
			return
		}

		principal, rerr := remote.ValidateToken(c.Request.Context(), token)
		if rerr != nil {
			abort(c, "Silahkan untuk login ulang")
			return
		}
		bind(c, principal)
	}
}

// RequireRole aborts with 403 unless the caller holds one of the given roles.
func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := FromContext(c.Request.Context())
		if !ok {
			abort(c, "No token provided.")
			return
		}
		if !p.HasRole(roles...) {
			c.AbortWithStatusJSON(403, gin.H{"success": false, "message": "Access Denied"})
			return
		}
		c.Next()
	}
}

// RequireModule aborts with 403 unless the caller may perform module.action.
// The permission argument uses the legacy "module.action" spelling.
func RequireModule(permission string) gin.HandlerFunc {
	module, action, found := strings.Cut(permission, ".")
	return func(c *gin.Context) {
		if !found {
			c.AbortWithStatusJSON(500, gin.H{"success": false, "message": "malformed permission"})
			return
		}
		p, ok := FromContext(c.Request.Context())
		if !ok {
			abort(c, "No token provided.")
			return
		}
		if !p.HasModule(module, action) {
			c.AbortWithStatusJSON(403, gin.H{"success": false, "message": "Access Denied"})
			return
		}
		c.Next()
	}
}

// ExtractToken pulls the bearer token from the Authorization header, tolerating
// the bare-token form the legacy mobile clients send, and falling back to the
// ?token= query parameter those clients also use.
func ExtractToken(c *gin.Context) string {
	if auth := c.GetHeader("Authorization"); auth != "" {
		if after, ok := strings.CutPrefix(auth, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
		return strings.TrimSpace(auth)
	}
	return c.Query("token")
}

func bind(c *gin.Context, p Principal) {
	c.Set(GinContextKey, p)
	c.Request = c.Request.WithContext(WithPrincipal(c.Request.Context(), p))
	c.Next()
}

func abort(c *gin.Context, message string) {
	c.AbortWithStatusJSON(401, gin.H{"success": false, "message": message})
}

// Gin returns the principal bound to a gin context.
func Gin(c *gin.Context) (Principal, bool) {
	v, ok := c.Get(GinContextKey)
	if !ok {
		return Principal{}, false
	}
	p, ok := v.(Principal)
	return p, ok
}
