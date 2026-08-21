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

	Auth *handlers.AuthHandler
	User *handlers.UserHandler
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
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Request-Id"},
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
	auth := api.Group("/auth")

	auth.POST("/login", d.Auth.Login)
	auth.POST("/register", d.Auth.Register)
	auth.POST("/refresh", d.Auth.Refresh)
	auth.GET("/check-available/:kind", d.Auth.CheckAvailability)
}

func registerProtected(api *gin.RouterGroup, d Deps) {
	protected := api.Group("")
	protected.Use(authctx.RequireAuth(d.Verifier, d.Remote))

	// Self-service.
	auth := protected.Group("/auth")
	auth.GET("/me", d.Auth.Me)
	auth.POST("/logout", d.Auth.Logout)
	auth.POST("/logout-all", d.Auth.LogoutAll)
	auth.POST("/change-password", d.Auth.ChangePassword)
	auth.POST("/register-member", authctx.RequireModule("collaboration.inviteMember"), d.Auth.RegisterMember)

	// User administration.
	users := protected.Group("/users")
	users.GET("", d.User.List)
	users.GET("/:id", d.User.Get)
	users.PUT("/me", d.User.UpdateMe)

	admin := users.Group("")
	admin.Use(authctx.RequireRole("superadmin", "admin"))
	admin.PUT("/:id", d.User.Update)
	admin.PUT("/:id/suspend", d.User.Suspend)
	admin.DELETE("/:id", d.User.Delete)

	// Permission management is a company-owner action, not a platform-admin one.
	users.PUT("/:id/permission",
		authctx.RequireModule("collaboration.manageMember"),
		d.User.SetPermission,
	)
}
