// Command server runs the authentication service.
//
// It listens on two ports: HTTP for the front ends, and gRPC for the other
// services. Both are served from one process and shut down together.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
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

	authService := services.NewAuthService(userRepo, sessionRepo, apiKeyRepo, deviceRepo, moduleRepo, accessRepo, auditRepo, signer, cacheClient, cfg)
	userService := services.NewUserService(userRepo, companyRepo, moduleRepo, accessRepo, sessionRepo, auditRepo, authService)

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
		Remote: localValidator{auth: authService},
		Auth:   handlers.NewAuthHandler(authService, userService),
		User:   handlers.NewUserHandler(userService),
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
