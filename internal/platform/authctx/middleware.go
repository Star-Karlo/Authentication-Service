package authctx

import (
	"context"
	"strings"
	"time"

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
	return RequireAuthWithRevocations(v, remote, nil)
}

// RequireAuthWithRevocations is RequireAuth plus a locally-held list of tokens
// that must no longer be accepted.
//
// A locally-verified token is otherwise valid until it expires, which with a
// two-hour lifetime means suspending somebody leaves them working for two
// hours. The list closes that without putting the authentication service on the
// critical path of every request: it is announced to, and answers from memory.
//
// A nil checker keeps the previous behaviour, so a service that has not been
// wired up yet still runs.
func RequireAuthWithRevocations(v *Verifier, remote RemoteValidator, revoked RevocationChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := ExtractToken(c)
		if token == "" {
			abort(c, "No token provided.")
			return
		}

		principal, issuedAt, err := v.VerifyWithIssuedAt(token)
		if err == nil && !principal.SingleDevice {
			// The one check that stands between a locally-verified token and
			// two hours of access it should no longer have.
			if revoked != nil && revoked.Revoked(principal.TokenID, principal.UserID, principal.CompanyID, issuedAt) {
				abort(c, "Akses Anda telah berubah. Silakan login ulang. "+
					"(Your access changed; please sign in again.)")
				return
			}
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
			// This is usually a single-device session that was DISPLACED —
			// the same account signed in somewhere else and that eviction is
			// immediate. "Please log in again" reads as expiry, which sends
			// whoever hits it looking at token lifetimes instead of at the
			// other browser tab they just used.
			abort(c, "Sesi Anda berakhir karena akun ini masuk di perangkat lain. "+
				"Silakan login ulang. (Signed in on another device.)")
			return
		}
		bind(c, principal)
	}
}

// RevocationChecker reports whether a token must no longer be accepted.
//
// Declared here rather than imported so authctx keeps no dependency on the
// package that implements it — the middleware needs the question, not the
// machinery behind the answer.
type RevocationChecker interface {
	Revoked(sessionID, userID, companyID string, issuedAt time.Time) bool
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

// RequirePlatformStaff aborts unless the caller is a Karlo employee.
//
// This is the only guard a tenant cannot satisfy by any arrangement of
// permissions or entitlement. It exists for the decisions that are Karlo's
// rather than the customer's — above all, which modules a company has bought.
// A company that could grant itself entitlement would have no commercial
// boundary at all, so this check must never be expressible as a permission key.
func RequirePlatformStaff() gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := FromContext(c.Request.Context())
		if !ok {
			abort(c, "No token provided.")
			return
		}
		if !p.IsPlatformStaff {
			c.AbortWithStatusJSON(403, gin.H{
				"success": false,
				"message": "This action is restricted to Karlo staff.",
			})
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
