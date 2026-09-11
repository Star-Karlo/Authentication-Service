package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/karlo/authentication-service/internal/models"
)

// RoleRepository owns the roles a company defines.
type RoleRepository struct{ db *gorm.DB }

func NewRoleRepository(db *gorm.DB) *RoleRepository { return &RoleRepository{db: db} }

// WithTx returns a repository that writes through the given transaction.
func (r *RoleRepository) WithTx(tx *gorm.DB) *RoleRepository {
	if tx == nil {
		return r
	}
	return &RoleRepository{db: tx}
}

// AdministratorRoleName is the role every company is created with.
const AdministratorRoleName = "Administrator"

// EnsureAdministrator returns the company's administrator role, creating it if
// it does not exist.
//
// Every company needs one from the moment it exists: the account that registers
// it has to be able to do everything, and there is no other way to grant that.
// It is is_system so a tidy-up cannot delete the only role that can administer
// the company — which is how a company locks itself out.
func (r *RoleRepository) EnsureAdministrator(ctx context.Context, companyID uuid.UUID) (*models.Role, error) {
	role := &models.Role{
		CompanyID: companyID,
		Name:      AdministratorRoleName,
		GrantsAll: true,
		IsSystem:  true,
	}
	description := "Full access to everything this company is entitled to. " +
		"Created automatically and cannot be deleted."
	role.Description = &description

	err := r.db.WithContext(ctx).Exec(`
		INSERT INTO roles (company_id, name, description, permissions, grants_all, is_system)
		VALUES (?, ?, ?, '{}'::text[], TRUE, TRUE)
		ON CONFLICT (company_id, name) DO UPDATE SET
			grants_all = TRUE, is_system = TRUE, updated_at = NOW()
	`, companyID, AdministratorRoleName, description).Error
	if err != nil {
		return nil, fmt.Errorf("repository: ensure administrator role: %w", err)
	}

	return r.FindByName(ctx, companyID, AdministratorRoleName)
}

func (r *RoleRepository) FindByName(ctx context.Context, companyID uuid.UUID, name string) (*models.Role, error) {
	var role models.Role
	err := r.db.WithContext(ctx).
		Where("company_id = ? AND name = ?", companyID, name).
		First(&role).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("repository: find role: %w", err)
	}
	return &role, nil
}

func (r *RoleRepository) FindByID(ctx context.Context, companyID, id uuid.UUID) (*models.Role, error) {
	var role models.Role
	err := r.db.WithContext(ctx).
		Where("id = ? AND company_id = ?", id, companyID).
		First(&role).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("repository: find role: %w", err)
	}
	return &role, nil
}

func (r *RoleRepository) ListForCompany(ctx context.Context, companyID uuid.UUID) ([]models.Role, error) {
	var out []models.Role
	err := r.db.WithContext(ctx).
		Where("company_id = ?", companyID).
		Order("is_system DESC, name").
		Find(&out).Error
	if err != nil {
		return nil, fmt.Errorf("repository: list roles: %w", err)
	}
	return out, nil
}

func (r *RoleRepository) Create(ctx context.Context, role *models.Role) error {
	err := r.db.WithContext(ctx).Create(role).Error
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return ErrConflict
		}
		return fmt.Errorf("repository: create role: %w", err)
	}
	return nil
}

func (r *RoleRepository) Update(ctx context.Context, companyID, id uuid.UUID, fields map[string]interface{}) error {
	res := r.db.WithContext(ctx).Model(&models.Role{}).
		Where("id = ? AND company_id = ?", id, companyID).
		Updates(fields)
	if res.Error != nil {
		return fmt.Errorf("repository: update role: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes a role.
//
// Refused for a system role, and the users.role_id foreign key is ON DELETE
// RESTRICT — so a role with people on it cannot be removed either. Both
// refusals are deliberate: silently leaving someone with no role would leave
// them signed in and able to do nothing, which reads as a broken account.
func (r *RoleRepository) Delete(ctx context.Context, companyID, id uuid.UUID) error {
	res := r.db.WithContext(ctx).
		Where("id = ? AND company_id = ? AND NOT is_system", id, companyID).
		Delete(&models.Role{})
	if res.Error != nil {
		return fmt.Errorf("repository: delete role: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// CountUsers reports how many accounts hold a role, so a caller can explain a
// refusal rather than surfacing a foreign key error.
func (r *RoleRepository) CountUsers(ctx context.Context, id uuid.UUID) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&models.User{}).
		Where("role_id = ? AND deleted_at IS NULL", id).Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("repository: count role holders: %w", err)
	}
	return n, nil
}
