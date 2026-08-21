package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/platform/query"
	"github.com/karlo/authentication-service/internal/repository"
)

// ErrForbidden signals an authorisation failure inside the service layer.
var ErrForbidden = errors.New("forbidden")

// UserService manages accounts and their permissions.
type UserService struct {
	users     *repository.UserRepository
	companies *repository.CompanyRepository
	sessions  *repository.SessionRepository
	audit     *repository.AuditRepository
	auth      *AuthService
}

func NewUserService(
	users *repository.UserRepository,
	companies *repository.CompanyRepository,
	sessions *repository.SessionRepository,
	audit *repository.AuditRepository,
	auth *AuthService,
) *UserService {
	return &UserService{users: users, companies: companies, sessions: sessions, audit: audit, auth: auth}
}

// RegisterInput describes a new account.
type RegisterInput struct {
	Username string
	Email    string
	Phone    string
	Password string
	FullName string
	Role     string
	// ParentID is set when a company invites a member; the new account inherits
	// that company and is subject to permission checks.
	ParentID  *uuid.UUID
	CompanyID *uuid.UUID
	// CompanyName creates a new company alongside a root account.
	CompanyName string
	Permission  models.Permission
}

// Register creates an account, and a company when the account is a root one.
func (s *UserService) Register(ctx context.Context, in RegisterInput) (*models.User, error) {
	if err := ValidatePasswordStrength(in.Password); err != nil {
		return nil, err
	}
	if in.Email == "" && in.Phone == "" && in.Username == "" {
		return nil, errors.New("one of email, phone or username is required")
	}
	if in.Role == "" {
		return nil, errors.New("role is required")
	}

	if err := s.assertIdentifiersFree(ctx, in); err != nil {
		return nil, err
	}

	hash, err := s.auth.HashPassword(in.Password)
	if err != nil {
		return nil, err
	}

	companyID := in.CompanyID
	accountType := "subAccount"

	// A registration with no parent and no company creates a new tenant.
	if in.ParentID == nil && companyID == nil {
		accountType = "mainAccount"
		company := &models.Company{
			Name: firstNonEmpty(in.CompanyName, in.FullName, in.Email),
			Role: in.Role,
			Settings: models.CompanySettings{
				PPNPercentage:   0.02,
				PPH23Percentage: 0.11,
			},
		}
		if err := s.companies.Create(ctx, company); err != nil {
			return nil, fmt.Errorf("register: %w", err)
		}
		companyID = &company.ID
	}

	user := &models.User{
		Username:     nilIfEmpty(strings.TrimSpace(in.Username)),
		Email:        nilIfEmpty(strings.ToLower(strings.TrimSpace(in.Email))),
		Phone:        nilIfEmpty(strings.TrimSpace(in.Phone)),
		PasswordHash: hash,
		FullName:     nilIfEmpty(in.FullName),
		Role:         in.Role,
		AccountType:  accountType,
		CompanyID:    companyID,
		ParentID:     in.ParentID,
		Permission:   in.Permission,
		Language:     "id",
	}
	if user.Permission == nil {
		user.Permission = models.Permission{}
	}

	if err := s.users.Create(ctx, user); err != nil {
		if errors.Is(err, repository.ErrConflict) {
			return nil, fmt.Errorf("an account with these details already exists")
		}
		return nil, fmt.Errorf("register: %w", err)
	}

	return user, nil
}

func (s *UserService) assertIdentifiersFree(ctx context.Context, in RegisterInput) error {
	checks := []struct {
		value string
		fn    func(context.Context, string) (bool, error)
		label string
	}{
		{strings.ToLower(strings.TrimSpace(in.Email)), s.users.ExistsByEmail, "email"},
		{strings.TrimSpace(in.Username), s.users.ExistsByUsername, "username"},
		{strings.TrimSpace(in.Phone), s.users.ExistsByPhone, "phone"},
	}
	for _, c := range checks {
		if c.value == "" {
			continue
		}
		taken, err := c.fn(ctx, c.value)
		if err != nil {
			return fmt.Errorf("register: check %s: %w", c.label, err)
		}
		if taken {
			return fmt.Errorf("%s is already registered", c.label)
		}
	}
	return nil
}

// GetByID resolves one user.
func (s *UserService) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	return s.users.FindByID(ctx, id)
}

// GetMany resolves several users, used by the gRPC batch endpoints.
func (s *UserService) GetMany(ctx context.Context, ids []uuid.UUID, includeDeleted bool) ([]models.User, error) {
	return s.users.FindByIDs(ctx, ids, includeDeleted)
}

// List pages accounts for an administrator.
func (s *UserService) List(ctx context.Context, p query.Params) ([]models.User, int64, error) {
	return s.users.List(ctx, p)
}

// ListCompanyMembers pages the members of one company.
func (s *UserService) ListCompanyMembers(ctx context.Context, companyID uuid.UUID, roles []string, p query.Params) ([]models.User, int64, error) {
	return s.users.ListByCompany(ctx, companyID, roles, p)
}

// profileUpdatable is the allowlist of fields a user may change on themselves.
// Anything not named here — role, permission, company, verification flags —
// cannot be set by the account holder, whatever the request body contains.
var profileUpdatable = map[string]string{
	"fullName":              "full_name",
	"phone":                 "phone",
	"address":               "address",
	"cityId":                "city_id",
	"photoUrl":              "photo_url",
	"language":              "language",
	"birthDate":             "birth_date",
	"emergencyContactName":  "emergency_contact_name",
	"emergencyContactPhone": "emergency_contact_phone",
}

// UpdateProfile applies a self-service profile change.
func (s *UserService) UpdateProfile(ctx context.Context, userID uuid.UUID, input map[string]interface{}) error {
	fields := projectAllowed(input, profileUpdatable)
	if len(fields) == 0 {
		return errors.New("no updatable fields supplied")
	}
	return s.users.UpdateFields(ctx, userID, fields)
}

// adminUpdatable additionally allows the fields only an administrator may set.
var adminUpdatable = mergeMaps(profileUpdatable, map[string]string{
	"role":            "role",
	"isVerified":      "is_verified",
	"isEmailVerified": "is_email_verified",
	"isPhoneVerified": "is_phone_verified",
	"email":           "email",
	"username":        "username",
})

// AdminUpdate applies an administrative change to another account.
func (s *UserService) AdminUpdate(ctx context.Context, actorID, targetID uuid.UUID, input map[string]interface{}) error {
	fields := projectAllowed(input, adminUpdatable)
	if len(fields) == 0 {
		return errors.New("no updatable fields supplied")
	}
	if err := s.users.UpdateFields(ctx, targetID, fields); err != nil {
		return err
	}
	s.auth.writeAudit(ctx, &models.AuditEntry{
		UserID: &targetID, ActorUserID: &actorID, Event: "user.updated", Succeeded: true,
		Detail: models.JSONMap{"fields": keysOf(fields)},
	})
	return nil
}

// SetPermission replaces a sub-account's permission map.
//
// Two rules are enforced. A root account cannot be given a permission map,
// because root accounts bypass the check and a map there would be misleading.
// And the actor must belong to the same company as the target.
func (s *UserService) SetPermission(ctx context.Context, actorID, targetID uuid.UUID, perm models.Permission) error {
	actor, err := s.users.FindByID(ctx, actorID)
	if err != nil {
		return err
	}
	target, err := s.users.FindByID(ctx, targetID)
	if err != nil {
		return err
	}

	if actor.CompanyID == nil || target.CompanyID == nil || *actor.CompanyID != *target.CompanyID {
		return ErrForbidden
	}
	if target.IsRootAccount() {
		return errors.New("a root account cannot carry a permission map")
	}

	if err := s.users.UpdateFields(ctx, targetID, map[string]interface{}{"permission": perm}); err != nil {
		return err
	}

	// The permission map is embedded in issued tokens, so it only takes effect
	// once those are gone. Revoking forces a refresh.
	if _, err := s.sessions.RevokeAllForUser(ctx, targetID); err != nil {
		return fmt.Errorf("permission updated but sessions not revoked: %w", err)
	}

	s.auth.writeAudit(ctx, &models.AuditEntry{
		UserID: &targetID, ActorUserID: &actorID,
		Event: models.AuditPermissionChange, Succeeded: true,
	})
	return nil
}

// SetSuspended suspends or restores an account, revoking sessions on suspend.
func (s *UserService) SetSuspended(ctx context.Context, actorID, targetID uuid.UUID, suspended bool) error {
	if err := s.users.UpdateFields(ctx, targetID, map[string]interface{}{"is_suspended": suspended}); err != nil {
		return err
	}

	event := models.AuditUserUnsuspended
	if suspended {
		event = models.AuditUserSuspended
		if _, err := s.sessions.RevokeAllForUser(ctx, targetID); err != nil {
			return fmt.Errorf("user suspended but sessions not revoked: %w", err)
		}
	}

	s.auth.writeAudit(ctx, &models.AuditEntry{
		UserID: &targetID, ActorUserID: &actorID, Event: event, Succeeded: true,
	})
	return nil
}

// Delete soft-deletes an account and ends its sessions.
func (s *UserService) Delete(ctx context.Context, actorID, targetID uuid.UUID) error {
	if _, err := s.sessions.RevokeAllForUser(ctx, targetID); err != nil {
		return fmt.Errorf("delete: revoke sessions: %w", err)
	}
	if err := s.users.SoftDelete(ctx, targetID); err != nil {
		return err
	}
	s.auth.writeAudit(ctx, &models.AuditEntry{
		UserID: &targetID, ActorUserID: &actorID, Event: models.AuditUserDeleted, Succeeded: true,
	})
	return nil
}

// CheckPermission answers a module.action question for one user.
func (s *UserService) CheckPermission(ctx context.Context, userID uuid.UUID, module, action string) (bool, error) {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return false, err
	}
	if user.IsSuspended {
		return false, nil
	}
	// Root accounts are unrestricted, matching the legacy rule.
	if user.IsRootAccount() {
		return true, nil
	}
	return user.Permission.Allows(module, action), nil
}

// IdentifierAvailable reports whether a login identifier is free.
func (s *UserService) IdentifierAvailable(ctx context.Context, kind, value string) (bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return false, errors.New("value is required")
	}

	var (
		taken bool
		err   error
	)
	switch kind {
	case "email":
		taken, err = s.users.ExistsByEmail(ctx, strings.ToLower(value))
	case "username":
		taken, err = s.users.ExistsByUsername(ctx, value)
	case "phone":
		taken, err = s.users.ExistsByPhone(ctx, value)
	default:
		return false, fmt.Errorf("unknown identifier kind %q", kind)
	}
	if err != nil {
		return false, err
	}
	return !taken, nil
}

// projectAllowed maps a client-supplied body onto database columns using an
// allowlist. Keys absent from the allowlist are dropped silently, which is the
// correct behaviour for a partial update: the caller asked for something they
// may not do, and the rest of their request is still valid.
func projectAllowed(input map[string]interface{}, allowed map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(input))
	for k, v := range input {
		if col, ok := allowed[k]; ok {
			out[col] = v
		}
	}
	return out
}

func mergeMaps(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func keysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return "Unnamed Company"
}

var _ = time.Now
