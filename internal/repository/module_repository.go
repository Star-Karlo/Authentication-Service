package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ModuleRepository reads and writes company entitlements.
type ModuleRepository struct{ db *gorm.DB }

func NewModuleRepository(db *gorm.DB) *ModuleRepository { return &ModuleRepository{db: db} }

// ActiveForCompany returns the module names a company currently holds.
//
// This runs on every token mint, so it is a single indexed query returning
// strings rather than whole rows. The validity window is evaluated in SQL so
// that an expired trial stops granting access without anything having to run.
func (r *ModuleRepository) ActiveForCompany(ctx context.Context, companyID uuid.UUID) ([]string, error) {
	var modules []string

	err := r.db.WithContext(ctx).
		Model(&models.CompanyModule{}).
		Where("company_id = ? AND enabled", companyID).
		Where("valid_from IS NULL OR valid_from <= CURRENT_DATE").
		Where("valid_until IS NULL OR valid_until >= CURRENT_DATE").
		Order("module").
		Pluck("module", &modules).Error
	if err != nil {
		return nil, fmt.Errorf("repository: active modules: %w", err)
	}

	return modules, nil
}

// ListForCompany returns the full entitlement rows, including disabled and
// expired ones, for an administration screen.
func (r *ModuleRepository) ListForCompany(ctx context.Context, companyID uuid.UUID) ([]models.CompanyModule, error) {
	var out []models.CompanyModule
	err := r.db.WithContext(ctx).
		Where("company_id = ?", companyID).
		Order("module").
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
			Columns: []clause.Column{{Name: "company_id"}, {Name: "module"}},
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
func (r *ModuleRepository) Revoke(ctx context.Context, companyID uuid.UUID, module string, actorID *uuid.UUID) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.CompanyModule{}).
			Where("company_id = ? AND module = ?", companyID, module).
			Updates(map[string]interface{}{"enabled": false})
		if res.Error != nil {
			return fmt.Errorf("repository: revoke module: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}

		return tx.Create(&models.CompanyModuleEvent{
			CompanyID:   companyID,
			Module:      module,
			Action:      models.ModuleRevoked,
			ActorUserID: actorID,
		}).Error
	})
}

// GrantDefaults gives a newly created company its starting entitlement.
//
// Called inside the registration transaction, so a company is never left with
// no modules — which would make it exist but be unusable.
func (r *ModuleRepository) GrantDefaults(ctx context.Context, tx *gorm.DB, companyID uuid.UUID, modules []string) error {
	if len(modules) == 0 {
		return nil
	}

	rows := make([]models.CompanyModule, 0, len(modules))
	for _, module := range modules {
		rows = append(rows, models.CompanyModule{
			CompanyID: companyID,
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
