// Package repository is the only place that talks to the database. Services
// depend on the interfaces declared here, not on GORM.
package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/platform/query"
	"gorm.io/gorm"
)

// ErrNotFound is returned when a lookup matches no row. Callers compare against
// this rather than gorm.ErrRecordNotFound, so the ORM stays behind the boundary.
var ErrNotFound = errors.New("repository: not found")

// ErrConflict is returned when a write violates a uniqueness constraint.
var ErrConflict = errors.New("repository: conflict")

// UserRepository reads and writes user rows.
type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// userListFields is the allowlist for filtering and sorting the user list.
// A field absent from this map cannot be referenced by a client at all.
var userListFields = query.FieldSet{
	"username":    "username",
	"email":       "email",
	"phone":       "phone",
	"fullName":    "full_name",
	"role":        "role",
	"accountType": "account_type",
	"isVerified":  "is_verified",
	"isSuspended": "is_suspended",
	"createdAt":   "created_at",
	"lastLoginAt": "last_login_at",
}

// UserListFields exposes the allowlist to the HTTP layer so it can parse query
// parameters against the same set the repository will honour.
func UserListFields() query.FieldSet { return userListFields }

// FindByID returns a live user.
func (r *UserRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).First(&user, "id = ?", id).Error
	return one(&user, err)
}

// FindByIDIncludingDeleted returns a user even if soft-deleted, for the audit
// and admin paths that must still resolve a name.
func (r *UserRepository) FindByIDIncludingDeleted(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Unscoped().First(&user, "id = ?", id).Error
	return one(&user, err)
}

// FindByIDs resolves many users at once, for batch flows such as notification
// audience expansion.
func (r *UserRepository) FindByIDs(ctx context.Context, ids []uuid.UUID, includeDeleted bool) ([]models.User, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	q := r.db.WithContext(ctx)
	if includeDeleted {
		q = q.Unscoped()
	}
	var users []models.User
	if err := q.Find(&users, "id IN ?", ids).Error; err != nil {
		return nil, fmt.Errorf("repository: find users by ids: %w", err)
	}
	return users, nil
}

// FindByIdentifier resolves a login identifier, which may be an email, a
// username or a phone number.
//
// The legacy implementation tried each in three sequential queries, which
// leaked which field matched through response timing. One query over all three
// columns avoids that and is a single round trip.
func (r *UserRepository) FindByIdentifier(ctx context.Context, identifier string) (*models.User, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return nil, ErrNotFound
	}

	var user models.User
	err := r.db.WithContext(ctx).
		Where("email = ? OR username = ? OR phone = ?", identifier, identifier, identifier).
		First(&user).Error
	return one(&user, err)
}

// ExistsByEmail reports whether a live account already uses this email.
func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	return r.exists(ctx, "email = ?", email)
}

func (r *UserRepository) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	return r.exists(ctx, "username = ?", username)
}

func (r *UserRepository) ExistsByPhone(ctx context.Context, phone string) (bool, error) {
	return r.exists(ctx, "phone = ?", phone)
}

func (r *UserRepository) exists(ctx context.Context, cond string, arg interface{}) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.User{}).Where(cond, arg).Limit(1).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("repository: exists check: %w", err)
	}
	return count > 0, nil
}

// Create inserts a user, translating a unique-violation into ErrConflict.
func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: %v", ErrConflict, err)
		}
		return fmt.Errorf("repository: create user: %w", err)
	}
	return nil
}

// UpdateFields applies a partial update.
//
// The caller passes a map built from an explicit allowlist, never a decoded
// request body. Writing a client-controlled map straight to the database is how
// the monolith allowed any field on an order to be overwritten by any caller.
func (r *UserRepository) UpdateFields(ctx context.Context, id uuid.UUID, fields map[string]interface{}) error {
	if len(fields) == 0 {
		return nil
	}
	res := r.db.WithContext(ctx).Model(&models.User{}).Where("id = ?", id).Updates(fields)
	if res.Error != nil {
		if isUniqueViolation(res.Error) {
			return fmt.Errorf("%w: %v", ErrConflict, res.Error)
		}
		return fmt.Errorf("repository: update user: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// SoftDelete marks a user deleted, preserving referential history.
func (r *UserRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	res := r.db.WithContext(ctx).Delete(&models.User{}, "id = ?", id)
	if res.Error != nil {
		return fmt.Errorf("repository: delete user: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ListByCompany pages the members of a company, optionally narrowed by role.
func (r *UserRepository) ListByCompany(ctx context.Context, companyID uuid.UUID, roles []string, p query.Params) ([]models.User, int64, error) {
	q := r.db.WithContext(ctx).Model(&models.User{}).Where("company_id = ?", companyID)
	if len(roles) > 0 {
		q = q.Where("role IN ?", roles)
	}
	q = applyFilters(q, p)

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("repository: count company members: %w", err)
	}

	var users []models.User
	err := applySorts(q, p, "created_at DESC").
		Offset(p.Offset()).
		Limit(p.PageSize).
		Find(&users).Error
	if err != nil {
		return nil, 0, fmt.Errorf("repository: list company members: %w", err)
	}
	return users, total, nil
}

// List pages users across all companies. Only administrators reach this.
func (r *UserRepository) List(ctx context.Context, p query.Params) ([]models.User, int64, error) {
	q := applyFilters(r.db.WithContext(ctx).Model(&models.User{}), p)

	if p.Search != "" {
		like := "%" + p.Search + "%"
		q = q.Where("full_name ILIKE ? OR email ILIKE ? OR username ILIKE ? OR phone ILIKE ?", like, like, like, like)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("repository: count users: %w", err)
	}

	var users []models.User
	err := applySorts(q, p, "created_at DESC").
		Offset(p.Offset()).
		Limit(p.PageSize).
		Find(&users).Error
	if err != nil {
		return nil, 0, fmt.Errorf("repository: list users: %w", err)
	}
	return users, total, nil
}

// TouchLastLogin records a successful authentication.
func (r *UserRepository) TouchLastLogin(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", id).
		Update("last_login_at", gorm.Expr("NOW()")).Error
}

func one[T any](v *T, err error) (*T, error) {
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("repository: query: %w", err)
	}
	return v, nil
}
