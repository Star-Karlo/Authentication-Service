// Package routes wires the HTTP surface.
//
// Every route below maps to exactly one handler that does exactly one thing.
// That is the deliberate difference from the monolith, where 183 registered
// routes resolved to 28 handlers and most paths returned the wrong collection.
package routes

import (
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerfiles "github.com/swaggo/files"
	ginswagger "github.com/swaggo/gin-swagger"

	// Imported for its side effect: the generated package registers the
	// OpenAPI document with the swagger runtime on init.
	_ "github.com/karlo/authentication-service/docs"
	"github.com/karlo/authentication-service/internal/config"
	"github.com/karlo/authentication-service/internal/handlers"
	"github.com/karlo/authentication-service/internal/middleware"
	"github.com/karlo/authentication-service/internal/platform/authctx"
)

// Deps are the constructed collaborators the router needs.
type Deps struct {
	Config   *config.Config
	Verifier *authctx.Verifier
	Remote   authctx.RemoteValidator

	// Revocations lets a locally-verified token be refused before it expires.
	Revocations authctx.RevocationChecker

	Catalog     *handlers.CatalogHandler
	Shippers    *handlers.ShipperHandler
	Merges      *handlers.MergeHandler
	Auth        *handlers.AuthHandler
	User        *handlers.UserHandler
	Entitlement *handlers.EntitlementHandler
	Companies   *handlers.CompanyHandler
	Roles       *handlers.RoleHandler
}

// Setup builds the gin engine.
func Setup(d Deps) *gin.Engine {
	if d.Config.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.RequestLogger())

	// The origin list is required configuration. cors.Default() allows every
	// origin, which on a credentialed API means any site can drive the browser
	// on a logged-in user's behalf.
	router.Use(cors.New(cors.Config{
		AllowOrigins:     d.Config.CORSAllowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Request-Id", "X-Acting-For"},
		ExposeHeaders:    []string{"X-Request-Id"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "authentication"})
	})
	router.GET("/ready", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	// The interactive API browser. It is served only outside production: the
	// document describes every endpoint and its shapes, which is exactly the
	// reconnaissance an attacker would otherwise have to guess at.
	if !d.Config.IsProduction() {
		// /swagger/index.html is the browser; /swagger/doc.json is the raw
		// document, which is what client generators want.
		router.GET("/swagger/*any", ginswagger.WrapHandler(swaggerfiles.Handler))
	}

	api := router.Group("/api/v1")
	registerPublic(api, d)
	registerProtected(api, d)

	return router
}

func registerPublic(api *gin.RouterGroup, d Deps) {
	// The claim pages are PUBLIC by necessity: whoever opens the link has no
	// Karlo account yet, so there is no token they could present. The link
	// itself is the credential — holding it is what proves it was given to
	// them — which is why it is hashed at rest and single-use.
	claim := api.Group("/claim")
	{
		claim.GET("/:token", d.Shippers.PreviewClaim)
		claim.POST("/:token", d.Shippers.Claim)
	}

	auth := api.Group("/auth")

	auth.POST("/login", d.Auth.Login)
	auth.POST("/register", d.Auth.Register)
	auth.POST("/refresh", d.Auth.Refresh)
	auth.GET("/check-available/:kind", d.Auth.CheckAvailability)
}

func registerProtected(api *gin.RouterGroup, d Deps) {
	protected := api.Group("")
	protected.Use(authctx.RequireAuthWithRevocations(d.Verifier, d.Remote, d.Revocations))

	// Self-service.
	auth := protected.Group("/auth")
	auth.GET("/me", d.Auth.Me)
	auth.POST("/logout", d.Auth.Logout)
	auth.POST("/logout-all", d.Auth.LogoutAll)
	auth.POST("/change-password", d.Auth.ChangePassword)
	auth.POST("/register-member", authctx.RequireModule("collaboration.inviteMember"), d.Auth.RegisterMember)

	// User administration.
	// The permission catalogue. Readable by anyone signed in, because a role
	// editor needs it and the list of keys the system defines is not itself
	// sensitive — what somebody HOLDS is, and that is elsewhere.
	// A company's own roles. Gated on the same permission as inviting members:
	// deciding what a colleague may do and deciding who the colleagues are is
	// the same job, held by the same person.
	roles := protected.Group("/roles")
	roles.Use(authctx.RequireModule("collaboration.manageMember"))
	{
		roles.GET("", d.Roles.List)
		roles.POST("", d.Roles.Create)
		roles.PUT("/:id", d.Roles.Update)
		roles.DELETE("/:id", d.Roles.Delete)
	}

	catalog := protected.Group("/permissions/catalog")
	{
		catalog.GET("", d.Catalog.List)

		// Rewording is an administrative act: it changes what every user of
		// this deployment reads on the permission screen.
		catalog.PUT("/:key/label",
			authctx.RequireModule("collaboration.inviteMember"),
			d.Catalog.SetLabel)
	}

	shippers := protected.Group("/shippers")
	{
		shippers.GET("", d.Shippers.List)
		shippers.POST("", authctx.RequireModule("collaboration.inviteMember"), d.Shippers.Create)
		// Issuing a link hands somebody administrator access to a company, so
		// it takes the same permission as inviting a member — which is what it
		// is, for a company that does not exist yet.
		shippers.POST("/:id/claim-link",
			authctx.RequireModule("collaboration.inviteMember"), d.Shippers.IssueClaimLink)
	}

	// Merging moves records between tenants, so it is platform staff only.
	companies := protected.Group("/companies")
	companies.Use(authctx.RequirePlatformStaff())
	{
		companies.POST("/:id/merge", d.Merges.Merge)
	}

	users := protected.Group("/users")
	users.GET("", d.User.List)
	users.GET("/:id", d.User.Get)
	users.PUT("/me", d.User.UpdateMe)

	// Managing a company's own people is the company's job, not Karlo's.
	//
	// These were guarded by RequireRole("superadmin","admin"). Migration
	// 000003 moved both of those to is_platform_staff, so no tenant role
	// satisfied the guard any longer and a company administrator could invite a
	// member and set their permissions but never suspend or remove one — the
	// customer had to raise a support ticket to take away a departing
	// employee's access, which is the worst possible thing to make slow.
	//
	// The permission keys express the intent directly, and the service layer
	// still confirms that actor and target share a company, so a key alone does
	// not let anyone reach into another tenant.
	users.PUT("/:id", authctx.RequireModule("collaboration.manageMember"), d.User.Update)
	users.PUT("/:id/suspend", authctx.RequireModule("collaboration.removeMember"), d.User.Suspend)
	users.DELETE("/:id", authctx.RequireModule("collaboration.removeMember"), d.User.Delete)

	// Permission management is a company-owner action, not a platform-admin one.
	// Which role a colleague holds. Separate from the generic user update
	// because the role must be checked against the target's company — the ids
	// are opaque, so a pasted id from another company would look fine.
	users.PUT("/:id/role",
		authctx.RequireModule("collaboration.manageMember"), d.User.AssignRole)

	users.PUT("/:id/permission",
		authctx.RequireModule("collaboration.manageMember"),
		d.User.SetPermission,
	)

	// Which PRODUCTS a member may use, as opposed to what they may do inside
	// one. Without this a company could not put its own people on a second
	// product it had bought.
	users.GET("/:id/access", authctx.RequireModule("collaboration.read"), d.User.ListAccess)
	users.PUT("/:id/access", authctx.RequireModule("collaboration.manageMember"), d.User.SetAccess)
	users.DELETE("/:id/access/:product",
		authctx.RequireModule("collaboration.manageMember"), d.User.RevokeAccess)

	registerAdmin(protected, d)
}

// registerAdmin mounts the Karlo staff surface: deciding what a company has
// bought.
//
// Guarded by RequirePlatformStaff rather than by a permission key, deliberately.
// A permission key is something a company can hold, and no arrangement of keys
// should ever let a customer widen their own entitlement — that decision is
// ours to make and theirs to pay for. The guard is the one check in the system
// that a tenant cannot satisfy at all.
func registerAdmin(protected *gin.RouterGroup, d Deps) {
	if d.Entitlement == nil {
		return
	}

	admin := protected.Group("/admin")
	admin.Use(authctx.RequirePlatformStaff())

	admin.GET("/features", d.Entitlement.Catalogue)

	// The platform-wide company directory. Registered before the
	// /companies/:id/entitlements group below so "companies" alone resolves
	// here rather than being read as a missing id.
	admin.GET("/companies", d.Companies.List)

	companies := admin.Group("/companies/:id/entitlements")
	companies.GET("", d.Entitlement.List)
	companies.PUT("", d.Entitlement.Grant)
	companies.GET("/history", d.Entitlement.History)
	companies.GET("/effective", d.Entitlement.Effective)
	companies.DELETE("/:product/:module", d.Entitlement.Revoke)
}
