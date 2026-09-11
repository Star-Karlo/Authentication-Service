package repository

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/platform/authctx"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ModuleRepository reads and writes company entitlements.
type ModuleRepository struct{ db *gorm.DB }

func NewModuleRepository(db *gorm.DB) *ModuleRepository { return &ModuleRepository{db: db} }

// WithTx returns a repository that writes through the given transaction.
func (r *ModuleRepository) WithTx(tx *gorm.DB) *ModuleRepository {
	if tx == nil {
		return r
	}
	return &ModuleRepository{db: tx}
}

// ActiveForCompany returns the module names a company currently holds.
//
// This runs on every token mint, so it is a single indexed query returning
// strings rather than whole rows. The validity window is evaluated in SQL so
// that an expired trial stops granting access without anything having to run.
func (r *ModuleRepository) ActiveForCompany(ctx context.Context, companyID uuid.UUID, product authctx.Product) ([]string, error) {
	// Resolved through the SAME function that fills a token, so an
	// administration screen and a token cannot describe the same company
	// differently. Reading company_modules directly here was a real bug: it
	// assumed the opt-in reading, so a tenant converted to opt-out was told it
	// held no modules — while its tokens carried the full set.
	//
	// The product filter is not optional. Without it a TMS screen would offer
	// FMS entitlements and vice versa, because the two catalogues share module
	// names that mean different things.
	//
	// Shared entitlements — accounting and telemetry, which belong to neither
	// product — are included alongside, since a permission gated by one of them
	// resolves whichever product the caller is in.
	features, err := entitlementFor(ctx, r.db, companyID)
	if err != nil {
		return nil, err
	}

	modules := append(
		append([]string{}, features[string(product)]...),
		features[string(authctx.ProductShared)]...,
	)
	sort.Strings(modules)
	return modules, nil
}

// ListForCompany returns the full entitlement rows, including disabled and
// expired ones, for an administration screen.
func (r *ModuleRepository) ListForCompany(ctx context.Context, companyID uuid.UUID) ([]models.CompanyModule, error) {
	var out []models.CompanyModule
	err := r.db.WithContext(ctx).
		Where("company_id = ?", companyID).
		Order("product, module").
		Find(&out).Error
	if err != nil {
		return nil, fmt.Errorf("repository: list company modules: %w", err)
	}
	return out, nil
}

// Grant creates or updates an entitlement, recording the change.
//
// The write and its history row are one transaction: an entitlement that
// changed with no record of who changed it is the thing this table exists to
// prevent.
func (r *ModuleRepository) Grant(ctx context.Context, m *models.CompanyModule, actorID *uuid.UUID) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "company_id"}, {Name: "product"}, {Name: "module"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"enabled", "valid_from", "valid_until", "limits",
				"granted_by_user_id", "note", "updated_at",
			}),
		}).Create(m).Error
		if err != nil {
			return fmt.Errorf("repository: grant module: %w", err)
		}

		action := models.ModuleGranted
		if !m.Enabled {
			action = models.ModuleRevoked
		}

		return tx.Create(&models.CompanyModuleEvent{
			CompanyID:   m.CompanyID,
			Product:     m.Product,
			Module:      m.Module,
			Action:      action,
			ActorUserID: actorID,
			Detail: models.JSONMap{
				"enabled":    m.Enabled,
				"validUntil": m.ValidUntil,
			},
		}).Error
	})
}

// Revoke disables an entitlement, keeping the row.
//
// Deleting instead would lose the fact that the company ever had the module,
// and with it the ability to answer "when did this stop working, and who
// stopped it".
func (r *ModuleRepository) Revoke(ctx context.Context, companyID uuid.UUID, product, module string, actorID *uuid.UUID) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.CompanyModule{}).
			Where("company_id = ? AND product = ? AND module = ?", companyID, product, module).
			Updates(map[string]interface{}{"enabled": false})
		if res.Error != nil {
			return fmt.Errorf("repository: revoke module: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}

		return tx.Create(&models.CompanyModuleEvent{
			CompanyID:   companyID,
			Product:     product,
			Module:      module,
			Action:      models.ModuleRevoked,
			ActorUserID: actorID,
		}).Error
	})
}

// GrantDefaults gives a newly created company its starting entitlement.
//
// tx must be the registration transaction, so a company is never left with no
// modules — which would make it exist but be unusable. Passing nil runs it on
// its own connection, which is correct only when there is no surrounding
// transaction to join.
func (r *ModuleRepository) GrantDefaults(ctx context.Context, tx *gorm.DB, companyID uuid.UUID, product authctx.Product, modules []string) error {
	if len(modules) == 0 {
		return nil
	}

	rows := make([]models.CompanyModule, 0, len(modules))
	for _, module := range modules {
		rows = append(rows, models.CompanyModule{
			CompanyID: companyID,
			Product:   string(product),
			Module:    module,
			Enabled:   true,
			Limits:    models.JSONMap{},
		})
	}

	db := tx
	if db == nil {
		db = r.db.WithContext(ctx)
	}

	err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&rows).Error
	if err != nil {
		return fmt.Errorf("repository: grant default modules: %w", err)
	}
	return nil
}

// History returns the entitlement changes for a company.
func (r *ModuleRepository) History(ctx context.Context, companyID uuid.UUID, limit int) ([]models.CompanyModuleEvent, error) {
	var out []models.CompanyModuleEvent
	err := r.db.WithContext(ctx).
		Where("company_id = ?", companyID).
		Order("created_at DESC").
		Limit(limit).
		Find(&out).Error
	if err != nil {
		return nil, fmt.Errorf("repository: module history: %w", err)
	}
	return out, nil
}

var _ = time.Now
