// Package bootstrap creates the first accounts on an empty environment.
//
// Run as `server bootstrap` from the deployed image, the way `server migrate`
// is. Migrations leave the schema and the permission catalogue but no company
// and no user, and the platform's own sign-up flow assumes a Karlo staff
// member already exists to grant the new company its features — so on a fresh
// database nobody can log in and nobody can be created. This is the one step
// that breaks that loop.
//
// Idempotent, and deliberately narrow. It creates ONE platform-staff account
// and its company, and refuses to run at all once any platform staff exists —
// so it cannot be used later to mint a second administrator from a shell.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/google/uuid"

	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/repository"
	"github.com/karlo/authentication-service/internal/services"
)

// Deps is what a bootstrap needs from the running service.
type Deps struct {
	Users     *repository.UserRepository
	Companies *repository.CompanyRepository
	Register  func(ctx context.Context, in services.RegisterInput) (*models.User, error)
}

// Run creates the first platform administrator from the environment:
//
//	BOOTSTRAP_ADMIN_EMAIL     — required
//	BOOTSTRAP_ADMIN_PASSWORD  — required; read once, never logged
//	BOOTSTRAP_ADMIN_NAME      — display name, default "Karlo Administrator"
//	BOOTSTRAP_COMPANY_NAME    — default "Karlo Platform"
//	BOOTSTRAP_COMPANY_ABBR    — default "KP"; used in agreement numbers
//
// Values come from the environment rather than flags so they can be injected
// as ECS secrets and never appear in a task definition or a shell history.
func Run(ctx context.Context, d Deps) error {
	email := strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_EMAIL"))
	password := os.Getenv("BOOTSTRAP_ADMIN_PASSWORD")
	if email == "" || password == "" {
		return errors.New("bootstrap: BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD are required")
	}
	if len(password) < 12 {
		return errors.New("bootstrap: the administrator password must be at least 12 characters")
	}

	// The guard. Any existing platform staff means this environment has been
	// bootstrapped; a second run is a mistake or an attempt, and either way
	// the answer is no.
	if n, err := d.Users.CountPlatformStaff(ctx); err != nil {
		return fmt.Errorf("bootstrap: checking for existing staff: %w", err)
	} else if n > 0 {
		slog.Info("bootstrap: platform staff already exists; nothing to do", "count", n)
		return nil
	}

	user, err := d.Register(ctx, services.RegisterInput{
		Email:       email,
		Password:    password,
		FullName:    envOr("BOOTSTRAP_ADMIN_NAME", "Karlo Administrator"),
		Role:        "admin",
		CompanyName: envOr("BOOTSTRAP_COMPANY_NAME", "Karlo Platform"),
	})
	if err != nil {
		return fmt.Errorf("bootstrap: creating administrator: %w", err)
	}

	// Register makes a company administrator. Platform staff is more than
	// that — it is what lets this account act for any client and grant
	// features — and Register has no reason to hand it out, so it is set here.
	if err := d.Users.UpdateFields(ctx, user.ID, map[string]interface{}{"is_platform_staff": true}); err != nil {
		return fmt.Errorf("bootstrap: marking platform staff: %w", err)
	}
	if user.CompanyID != nil {
		if err := d.Companies.UpdateFields(ctx, *user.CompanyID, map[string]interface{}{
			"abbreviation": envOr("BOOTSTRAP_COMPANY_ABBR", "KP"),
		}); err != nil {
			return fmt.Errorf("bootstrap: setting company abbreviation: %w", err)
		}
	}

	slog.Info("bootstrap: platform administrator created", "email", email, "userId", user.ID, "companyId", deref(user.CompanyID))
	return nil
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func deref(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}
