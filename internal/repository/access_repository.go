package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// AccessRepository assembles a person's access across products.
type AccessRepository struct{ db *gorm.DB }

func NewAccessRepository(db *gorm.DB) *AccessRepository { return &AccessRepository{db: db} }

// BuildAccess assembles the per-product access map that goes into a token.
//
// Two reads, merged: the user's own rows (which products they may use, in what
// role, with which permissions) and the company's entitlement per product. Both
// are needed because access is their intersection, and both are embedded so
// that no service has to ask again on the request path.
//
// A product the user has no row for is absent from the result — which is how
// "this person only uses FMS" is expressed.
func (r *AccessRepository) BuildAccess(ctx context.Context, userID uuid.UUID, companyID *uuid.UUID) (map[authctx.Product]authctx.ProductAccess, error) {
	var rows []struct {
		Product     string
		Role        string
		Permissions pq.StringArray `gorm:"type:text[]"`
	}

	err := r.db.WithContext(ctx).
		Table("user_product_access").
		Select("product, role, permissions").
		Where("user_id = ? AND enabled", userID).
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("repository: load product access: %w", err)
	}

	if len(rows) == 0 {
		return nil, nil
	}

	// Entitlement, per product. A user with no company has none — which is
	// correct: they can hold permissions but nothing gates through.
	features := map[string][]string{}
	if companyID != nil {
		var entitlements []struct {
			Product string
			Module  string
		}
		err := r.db.WithContext(ctx).
			Table("company_modules").
			Select("product, module").
			Where("company_id = ? AND enabled", *companyID).
			Where("valid_from IS NULL OR valid_from <= CURRENT_DATE").
			Where("valid_until IS NULL OR valid_until >= CURRENT_DATE").
			Scan(&entitlements).Error
		if err != nil {
			return nil, fmt.Errorf("repository: load entitlement: %w", err)
		}
		for _, e := range entitlements {
			features[e.Product] = append(features[e.Product], e.Module)
		}
	}

	out := make(map[authctx.Product]authctx.ProductAccess, len(rows))
	for _, row := range rows {
		product := authctx.Product(row.Product)
		out[product] = authctx.ProductAccess{
			Role:        row.Role,
			Permissions: []string(row.Permissions),
			// Shared entitlements (accounting, telemetry) belong to neither
			// product, so they are folded into every product's feature list.
			// A permission gated by `accounting` then resolves whichever
			// product the user is in, which is the point of them being shared.
			Features: append(append([]string{}, features[row.Product]...), features["shared"]...),
		}
	}

	return out, nil
}

// GrantProductAccess gives a person access to a product, or updates it.
func (r *AccessRepository) GrantProductAccess(ctx context.Context, access *models.ProductAccess) error {
	err := r.db.WithContext(ctx).Exec(`
		INSERT INTO user_product_access (user_id, product, role, permissions, enabled, granted_by_user_id)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (user_id, product) DO UPDATE SET
			role = EXCLUDED.role,
			permissions = EXCLUDED.permissions,
			enabled = EXCLUDED.enabled,
			granted_by_user_id = EXCLUDED.granted_by_user_id,
			updated_at = NOW()
	`, access.UserID, access.Product, access.Role,
		pq.StringArray(access.Permissions), access.Enabled, access.GrantedByUserID).Error
	if err != nil {
		return fmt.Errorf("repository: grant product access: %w", err)
	}
	return nil
}

// RevokeProductAccess disables a person's access to a product, keeping the row
// so the grant history survives.
func (r *AccessRepository) RevokeProductAccess(ctx context.Context, userID uuid.UUID, product string) error {
	res := r.db.WithContext(ctx).Exec(
		`UPDATE user_product_access SET enabled = FALSE, updated_at = NOW()
		 WHERE user_id = ? AND product = ?`, userID, product)
	if res.Error != nil {
		return fmt.Errorf("repository: revoke product access: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ListForUser returns every product access row a person holds.
func (r *AccessRepository) ListForUser(ctx context.Context, userID uuid.UUID) ([]models.ProductAccess, error) {
	var out []models.ProductAccess
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("product").
		Find(&out).Error
	if err != nil {
		return nil, fmt.Errorf("repository: list product access: %w", err)
	}
	return out, nil
}
