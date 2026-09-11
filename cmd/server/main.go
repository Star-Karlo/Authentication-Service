// Command server runs the authentication service.
//
// It listens on two ports: HTTP for the front ends, and gRPC for the other
// services. Both are served from one process and shut down together.
package main

import (
	"context"
	"errors"
	"github.com/karlo/authentication-service/internal/platform/bootstrap"
	"github.com/karlo/authentication-service/internal/platform/dbmigrate"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/karlo/authentication-service/internal/config"
	"github.com/karlo/authentication-service/internal/grpcserver"
	"github.com/karlo/authentication-service/internal/handlers"
	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/karlo/authentication-service/internal/platform/cache"
	authv1 "github.com/karlo/authentication-service/internal/platform/genproto/karlo/auth/v1"
	"github.com/karlo/authentication-service/internal/platform/grpcutil"
	"github.com/karlo/authentication-service/internal/platform/logger"
	"github.com/karlo/authentication-service/internal/platform/revocation"
	"github.com/karlo/authentication-service/internal/repository"
	"github.com/karlo/authentication-service/internal/routes"
	"github.com/karlo/authentication-service/internal/services"
)

// @title           Karlo Authentication API
// @version         1.0
// @description     Identity, company membership, sessions, permissions and API keys.\n\nThis service is the authority on who a caller is. It signs RS256 tokens with a private key it alone holds; every other service verifies them locally with the public key.
// @termsOfService  https://karlo.co.id/terms
//
// @contact.name    Karlo Engineering
// @contact.email   engineering@karlo.co.id
//
// @host            localhost:5001
// @BasePath        /api/v1
// @schemes         http https
//
// @securityDefinitions.apikey BearerAuth
// @in                         header
// @name                       Authorization
// @description                RS256 access token issued by the authentication service, as "Bearer <token>".
func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// `server migrate`: bring the schema up to date and exit. Run as a one-off
	// ECS task from the same image and secrets as the service, which is the
	// only place RDS can be reached from. Exits non-zero on failure so the
	// task — and whatever invoked it — sees the failure.
	// Matched anywhere in the arguments, not only at [1]: an ECS command
	// override is appended to the image's ENTRYPOINT, so a caller that names
	// the binary again puts "migrate" at [2]. Reading only [1] made that a
	// silent no-op — the task started the server instead of migrating.
	if slices.Contains(os.Args[1:], "migrate") {
		// /migrations is where the Dockerfile puts them. Overridable so the
		// same command works from a checkout, where they are ./migrations.
		dir := os.Getenv("MIGRATIONS_DIR")
		if dir == "" {
			dir = "/migrations"
		}
		return dbmigrate.Run(cfg.Database.DSN(), cfg.Database.Name, dir)
	}

	// Logs go to stdout as JSON, and additionally to Fluentd when
	// FLUENTD_HOST is set. An unreachable collector degrades to
	// stdout-only rather than stopping the service.
	// This service belongs to TMS; authctx resolves the convenience helpers
	// (HasModule, Role, HasRole) against it.
	authctx.SetProduct(authctx.ProductTMS)

	logger.InitFromEnv("authentication")
	defer logger.Close()

	// The signing key is loaded before anything else. This service cannot do
	// its job without one, and discovering that at first login would be worse.
	signer, err := authctx.NewSignerFromEnv()
	if err != nil {
		return err
	}

	db, err := config.ConnectPostgres(cfg)
	if err != nil {
		return err
	}

	// Optional. Without REDIS_ADDR this is a no-op and the login rate limiter
	// falls back to counting audit rows.
	cacheClient := cache.FromEnv("authentication")

	// Lives for the process: the watcher runs until shutdown.
	watchCtx, stopWatching := context.WithCancel(context.Background())
	defer stopWatching()

	// Revocations. The authentication service both announces them — when a
	// session ends, a role changes or entitlement moves — and honours them,
	// since its own routes are locally verified like everyone else's.
	revocationChecker, revocationStore := revocation.FromEnv(watchCtx, "authentication", cfg.AccessTokenTTL)
	defer func() {
		if err := cacheClient.Close(); err != nil {
			slog.Error("cache close failed", "error", err)
		}
	}()

	userRepo := repository.NewUserRepository(db)
	companyRepo := repository.NewCompanyRepository(db)
	sessionRepo := repository.NewSessionRepository(db)
	apiKeyRepo := repository.NewAPIKeyRepository(db)
	deviceRepo := repository.NewDeviceTokenRepository(db)
	auditRepo := repository.NewAuditRepository(db)
	moduleRepo := repository.NewModuleRepository(db)
	accessRepo := repository.NewAccessRepository(db)
	// Refuse to start on a malformed catalogue.
	//
	// Fatal rather than logged: an ungated permission grants access to everyone
	// regardless of what their company bought, and a permission gated by a
	// feature that does not exist can never be granted at all. Both are silent
	// in production and obvious here.
	if err := authctx.ValidateCatalogs(); err != nil {
		slog.Error("refusing to start", "error", err)
		os.Exit(1)
	}

	roleRepo := repository.NewRoleRepository(db)
	catalogRepo := repository.NewCatalogRepository(db)
	shipperService := services.NewShipperService(db, auditRepo)
	mergeService := services.NewMergeService(db, auditRepo)

	// Publish the permission keys this build declares, so a role editor has
	// something to query. Code declares; the table reflects — a row here for a
	// key the code does not define is marked inactive and never honoured.
	//
	// A failure is logged rather than fatal: the catalogue is what UIs read,
	// not what access checks consult, so a stale copy degrades a screen rather
	// than granting or denying anything.
	if err := catalogRepo.Sync(context.Background()); err != nil {
		slog.Error("could not sync the permission catalogue; role editors may "+
			"show a stale list, but access checks are unaffected", "error", err)
	}

	if revocationStore != nil {
		sessionRepo.SetAnnouncer(revocationStore)
	}

	authService := services.NewAuthService(userRepo, sessionRepo, apiKeyRepo, deviceRepo, moduleRepo, accessRepo, auditRepo, signer, cacheClient, cfg)
	userService := services.NewUserService(userRepo, roleRepo, companyRepo, moduleRepo, accessRepo, sessionRepo, auditRepo, authService)

	// `server bootstrap`: create the first platform administrator and exit.
	// Sits here, after the services exist, because it reuses Register rather
	// than reimplementing password hashing and role assignment.
	if slices.Contains(os.Args[1:], "bootstrap") {
		return bootstrap.Run(context.Background(), bootstrap.Deps{
			Users:     userRepo,
			Companies: companyRepo,
			Register:  userService.Register,
		})
	}
	entitlementService := services.NewEntitlementService(moduleRepo, companyRepo, auditRepo)
	if revocationStore != nil {
		entitlementService.SetAnnouncer(revocationStore)
	}

	grpcSrv := grpcutil.NewServer(grpcutil.ServerConfig{
		Service:               "authentication",
		Addr:                  ":" + cfg.GRPCPort,
		Verifier:              signer.Public(),
		AcceptedServiceTokens: cfg.AcceptedServiceTokens,
		EnableReflection:      !cfg.IsProduction(),
	})
	authv1.RegisterAuthServiceServer(
		grpcSrv.Registrar(),
		grpcserver.New(authService, userService, companyRepo, accessRepo, deviceRepo, userRepo),
	)

	router := routes.Setup(routes.Deps{
		Config:   cfg,
		Verifier: signer.Public(),
		// This service validates tokens itself, so it is its own remote
		// validator: API keys and single-device sessions resolve in-process.
		Remote:      localValidator{auth: authService},
		Revocations: revocationChecker,
		Catalog:     handlers.NewCatalogHandler(catalogRepo),
		Shippers:    handlers.NewShipperHandler(shipperService, authService.HashPassword),
		Merges:      handlers.NewMergeHandler(mergeService),
		Auth:        handlers.NewAuthHandler(authService, userService),
		User:        handlers.NewUserHandler(userService),
		// The Karlo staff surface for deciding what a company has bought.
		Entitlement: handlers.NewEntitlementHandler(entitlementService),
		Companies:   handlers.NewCompanyHandler(companyRepo),
		Roles:       handlers.NewRoleHandler(roleRepo),
	})

	httpSrv := &http.Server{
		Addr:              ":" + cfg.HTTPPort,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 2)

	go func() {
		slog.Info("http server listening", "addr", httpSrv.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	go func() {
		if err := grpcSrv.Serve(); err != nil {
			errCh <- err
		}
	}()

	// Prune expired sessions hourly. Without this the sessions table grows
	// without bound, since revocation is a timestamp rather than a delete.
	stopCleanup := startSessionCleanup(sessionRepo)
	defer stopCleanup()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case sig := <-quit:
		slog.Info("shutting down", "signal", sig.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(ctx); err != nil {
		slog.Error("http shutdown failed", "error", err)
	}
	grpcSrv.Shutdown(ctx)

	if sqlDB, err := db.DB(); err == nil {
		if err := sqlDB.Close(); err != nil {
			slog.Error("database close failed", "error", err)
		}
	}

	slog.Info("stopped")
	return nil
}

// localValidator adapts the auth service to the RemoteValidator interface the
// shared middleware expects.
type localValidator struct {
	auth *services.AuthService
}

func (l localValidator) ValidateToken(ctx context.Context, token string) (authctx.Principal, error) {
	principal, _, err := l.auth.ValidateToken(ctx, token)
	return principal, err
}

// startSessionCleanup runs the expired-session sweep until the returned
// function is called.
func startSessionCleanup(sessions *repository.SessionRepository) func() {
	ticker := time.NewTicker(time.Hour)
	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				// Keep a grace period so a session that just expired is still
				// visible for debugging a "why was I logged out" report.
				cutoff := time.Now().Add(-7 * 24 * time.Hour)
				n, err := sessions.DeleteExpired(ctx, cutoff)
				cancel()
				if err != nil {
					slog.Error("session cleanup failed", "error", err)
					continue
				}
				if n > 0 {
					slog.Info("pruned expired sessions", "count", n)
				}
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()

	return func() { close(done) }
}
