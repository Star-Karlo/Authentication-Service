package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/karlo/authentication-service/internal/models"
)

// MergeService folds one company into another.
//
// Duplicates are unavoidable: two transporters can each create a placeholder
// for the same shipper without knowing its tax number, and nothing at that
// moment can tell they are the same business. They surface later — when the
// shipper claims its company and supplies an NPWP that already exists.
//
// The loser is KEPT and points at the winner rather than being deleted. Orders,
// agreements and invoices live in another service and reference this id;
// deleting the row would break them, and a transaction spanning both services
// is not something this one can offer. A forwarding pointer lets every service
// resolve an old id correctly and move its own rows when it can.
type MergeService struct {
	db    *gorm.DB
	audit auditWriter
}

// auditWriter is the slice of the audit repository this service needs,
// declared here so the merge logic can be read without the rest of it.
type auditWriter interface {
	Write(ctx context.Context, e *models.AuditEntry) error
}

func NewMergeService(db *gorm.DB, audit auditWriter) *MergeService {
	return &MergeService{db: db, audit: audit}
}

var (
	// ErrMergeIntoSelf guards the obvious mistake, which would otherwise write
	// a row pointing at itself and make resolution loop forever.
	ErrMergeIntoSelf = errors.New("a company cannot be merged into itself")

	// ErrAlreadyMerged stops a chain forming. Resolution follows one hop; a
	// chain would need a loop, and a loop needs a cycle check, and none of that
	// is worth carrying when the caller can simply merge into the survivor.
	ErrAlreadyMerged = errors.New("that company has already been merged into another")

	// ErrSurvivorHasUsers is not an error about the survivor — see Merge.
	ErrSurvivorHasUsers = errors.New("both companies have users; merging would move people between tenants")
)

// MergeResult describes what moved.
type MergeResult struct {
	SurvivorID uuid.UUID `json:"survivorId"`
	MergedID   uuid.UUID `json:"mergedId"`
	UsersMoved int64     `json:"usersMoved"`
	LinksMoved int64     `json:"linksMoved"`
}

// Merge folds `duplicate` into `survivor`.
//
// Both companies must not hold users. That restriction is deliberate and worth
// stating: merging two companies that each have people signed in would move
// accounts between tenants, and every session those people hold carries a
// company id that would silently become wrong. The realistic case does not need
// it — a duplicate placeholder has no users at all, which is what makes it a
// placeholder — so the safe subset covers the actual problem.
func (s *MergeService) Merge(ctx context.Context, survivorID, duplicateID uuid.UUID, actorID *uuid.UUID) (*MergeResult, error) {
	if survivorID == duplicateID {
		return nil, ErrMergeIntoSelf
	}

	result := &MergeResult{SurvivorID: survivorID, MergedID: duplicateID}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Lock both rows, lowest id first.
		//
		// Ordering matters: two merges running at once and locking in opposite
		// orders would deadlock. Sorting gives every caller the same sequence.
		first, second := survivorID, duplicateID
		if second.String() < first.String() {
			first, second = second, first
		}
		var locked []models.Company
		if err := tx.Raw(`SELECT * FROM companies WHERE id IN (?, ?) ORDER BY id FOR UPDATE`,
			first, second).Scan(&locked).Error; err != nil {
			return fmt.Errorf("merge: lock companies: %w", err)
		}
		if len(locked) != 2 {
			return fmt.Errorf("%w: one of the companies does not exist", ErrValidation)
		}

		var survivor, duplicate models.Company
		for _, c := range locked {
			if c.ID == survivorID {
				survivor = c
			} else {
				duplicate = c
			}
		}

		if duplicate.MergedIntoCompanyID != nil {
			return ErrAlreadyMerged
		}
		if survivor.MergedIntoCompanyID != nil {
			return fmt.Errorf("%w: merge into the surviving company instead", ErrAlreadyMerged)
		}

		// Only one side may have people.
		var duplicateUsers int64
		if err := tx.Model(&models.User{}).
			Where("company_id = ? AND deleted_at IS NULL", duplicateID).
			Count(&duplicateUsers).Error; err != nil {
			return fmt.Errorf("merge: count users: %w", err)
		}
		if duplicateUsers > 0 {
			var survivorUsers int64
			if err := tx.Model(&models.User{}).
				Where("company_id = ? AND deleted_at IS NULL", survivorID).
				Count(&survivorUsers).Error; err != nil {
				return fmt.Errorf("merge: count users: %w", err)
			}
			if survivorUsers > 0 {
				return ErrSurvivorHasUsers
			}
		}

		// Move the people, if the duplicate had any.
		moved := tx.Exec(`UPDATE users SET company_id = ?, updated_at = NOW() WHERE company_id = ?`,
			survivorID, duplicateID)
		if moved.Error != nil {
			return fmt.Errorf("merge: move users: %w", moved.Error)
		}
		result.UsersMoved = moved.RowsAffected

		// Move the transporter relationships, skipping any the survivor
		// already has — the same transporter may deal with both duplicates,
		// which is precisely how the duplication was noticed.
		links := tx.Exec(`
			INSERT INTO company_links (transporter_company_id, shipper_company_id, linked_by_user_id)
			SELECT transporter_company_id, ?, linked_by_user_id
			FROM company_links WHERE shipper_company_id = ?
			ON CONFLICT DO NOTHING
		`, survivorID, duplicateID)
		if links.Error != nil {
			return fmt.Errorf("merge: move links: %w", links.Error)
		}
		result.LinksMoved = links.RowsAffected
		if err := tx.Exec(`DELETE FROM company_links WHERE shipper_company_id = ?`, duplicateID).Error; err != nil {
			return fmt.Errorf("merge: clear old links: %w", err)
		}

		// Fill gaps on the survivor from the duplicate.
		//
		// ORDER MATTERS. The duplicate's tax numbers are read and cleared
		// BEFORE they are written to the survivor: the unique index covers
		// every row that is not soft-deleted, so copying first would leave both
		// rows holding the same number for the length of one statement, and the
		// index refuses it. Clearing first is the only order that works.
		var carried struct {
			NPWP        *string
			NIB         *string
			Address     *string
			CityID      *string
			BankAccount *string
		}
		if err := tx.Raw(`
			SELECT npwp, nib, address, city_id, bank_account::text AS bank_account
			FROM companies WHERE id = ?
		`, duplicateID).Scan(&carried).Error; err != nil {
			return fmt.Errorf("merge: read the duplicate's details: %w", err)
		}

		// Release the identifiers, and mark the row merged in the same
		// statement so it is never briefly both live and stripped.
		if err := tx.Exec(`
			UPDATE companies SET
				npwp = NULL, nib = NULL,
				merged_into_company_id = ?, merged_at = NOW(),
				deleted_at = NOW(), updated_at = NOW()
			WHERE id = ?
		`, survivorID, duplicateID).Error; err != nil {
			return fmt.Errorf("merge: mark merged: %w", err)
		}

		// Now the survivor can take them. Only where it has nothing of its own:
		// the survivor is the record being kept, so its values win, but a
		// detail only the duplicate carried is worth keeping rather than
		// discarding.
		if err := tx.Exec(`
			UPDATE companies SET
				npwp         = COALESCE(npwp, ?),
				nib          = COALESCE(nib, ?),
				address      = COALESCE(address, ?),
				city_id      = COALESCE(city_id, ?),
				bank_account = COALESCE(bank_account, ?::jsonb),
				updated_at   = NOW()
			WHERE id = ?
		`, carried.NPWP, carried.NIB, carried.Address, carried.CityID,
			carried.BankAccount, survivorID).Error; err != nil {
			return fmt.Errorf("merge: carry over details: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Recorded after the transaction commits: an audit line for a merge that
	// was rolled back would be worse than none.
	if err := s.audit.Write(ctx, &models.AuditEntry{
		ActorUserID: actorID,
		Event:       models.AuditCompanyMerged,
		Succeeded:   true,
		Detail: models.JSONMap{
			"survivorId": survivorID.String(),
			"mergedId":   duplicateID.String(),
			"usersMoved": result.UsersMoved,
		},
	}); err != nil {
		slog.WarnContext(ctx, "companies merged but the audit line was not written",
			"survivor", survivorID, "merged", duplicateID, "error", err)
	}

	slog.InfoContext(ctx, "companies merged",
		"survivor", survivorID, "merged", duplicateID, "users_moved", result.UsersMoved)

	return result, nil
}

// Resolve follows a merge pointer to the company that now holds the records.
//
// One hop only, because Merge refuses to create chains. Other services call
// this when they hold an id that may be stale.
func (s *MergeService) Resolve(ctx context.Context, companyID uuid.UUID) (uuid.UUID, error) {
	// Cast to text and parse: GORM cannot decode a uuid column straight into
	// uuid.UUID here.
	var target *string
	err := s.db.WithContext(ctx).
		Raw(`SELECT merged_into_company_id::text FROM companies WHERE id = ?`, companyID).
		Scan(&target).Error
	if err != nil {
		return uuid.Nil, fmt.Errorf("resolve company: %w", err)
	}
	if target == nil || *target == "" {
		return companyID, nil
	}
	resolved, perr := uuid.Parse(*target)
	if perr != nil {
		return uuid.Nil, fmt.Errorf("resolve company: unreadable target %q: %w", *target, perr)
	}
	return resolved, nil
}
