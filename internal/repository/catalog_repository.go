package repository

import (
	"context"
	"fmt"
	"log/slog"

	"gorm.io/gorm"

	"github.com/karlo/authentication-service/internal/platform/authctx"
)

// CatalogRepository keeps the queryable copy of the permission catalogue in
// step with what the code declares.
type CatalogRepository struct{ db *gorm.DB }

func NewCatalogRepository(db *gorm.DB) *CatalogRepository { return &CatalogRepository{db: db} }

// CatalogEntry is one row as a caller sees it, with the label already resolved.
type CatalogEntry struct {
	Key     string `json:"key"`
	Product string `json:"product"`
	Feature string `json:"feature"`
	Group   string `json:"group"`

	// Label is the override where one exists, otherwise the code's default.
	// Resolved here so no caller has to know the distinction.
	Label string `json:"label"`

	// DefaultLabel lets an editor show what clearing the override would give.
	DefaultLabel string `json:"defaultLabel"`
	IsOverridden bool   `json:"isOverridden"`

	SortOrder int  `json:"sortOrder"`
	IsActive  bool `json:"isActive"`
}

// Sync writes every key the code declares into the table.
//
// Runs at startup. Upserts rather than replaces, so an edited label survives —
// only the code-supplied defaults are refreshed. Keys the code no longer
// declares are marked inactive rather than deleted: a role may still list one,
// and deleting the row would hide that rather than surface it.
func (r *CatalogRepository) Sync(ctx context.Context) error {
	type declared struct {
		product string
		entries authctx.Catalog
	}
	catalogues := []declared{
		{string(authctx.ProductTMS), authctx.CatalogFor(authctx.ProductTMS)},
		{string(authctx.ProductFMS), authctx.CatalogFor(authctx.ProductFMS)},
	}

	total := 0
	for _, c := range catalogues {
		// Ordered by group then key so sort_order is stable between runs;
		// otherwise map iteration would reshuffle the editor on every restart.
		keys := make([]string, 0, len(c.entries))
		for k := range c.entries {
			keys = append(keys, k)
		}
		sortStrings(keys)

		for i, key := range keys {
			p := c.entries[key]
			err := r.db.WithContext(ctx).Exec(`
				INSERT INTO permission_catalog
					(key, product, feature, group_name, label, sort_order, is_active, synced_at)
				VALUES (?, ?, ?, ?, ?, ?, TRUE, NOW())
				ON CONFLICT (product, key) DO UPDATE SET
					feature    = EXCLUDED.feature,
					group_name = EXCLUDED.group_name,
					label      = EXCLUDED.label,
					sort_order = EXCLUDED.sort_order,
					is_active  = TRUE,
					synced_at  = NOW(),
					updated_at = NOW()
			`, key, c.product, p.Feature, p.Group, p.Label, i).Error
			if err != nil {
				return fmt.Errorf("repository: sync catalogue %s/%s: %w", c.product, key, err)
			}
			total++
		}

		// Anything not touched by this run is no longer declared.
		res := r.db.WithContext(ctx).Exec(`
			UPDATE permission_catalog
			SET is_active = FALSE, updated_at = NOW()
			WHERE product = ? AND is_active
			  AND (synced_at IS NULL OR synced_at < NOW() - INTERVAL '1 second')
		`, c.product)
		if res.Error != nil {
			return fmt.Errorf("repository: retire catalogue keys: %w", res.Error)
		}
		if res.RowsAffected > 0 {
			// Worth saying out loud: a retired key may still be listed on a
			// role, where it now grants nothing.
			slog.WarnContext(ctx, "permission keys are no longer declared by the code "+
				"and have been marked inactive; any role still listing them grants nothing for those keys",
				"product", c.product, "count", res.RowsAffected)
		}
	}

	slog.InfoContext(ctx, "permission catalogue synced", "keys", total)
	return nil
}

// List returns the catalogue for one product, ready for a role editor.
func (r *CatalogRepository) List(ctx context.Context, product string, includeInactive bool) ([]CatalogEntry, error) {
	var rows []struct {
		Key           string
		Product       string
		Feature       string
		GroupName     string
		Label         string
		LabelOverride *string
		SortOrder     int
		IsActive      bool
	}

	q := r.db.WithContext(ctx).
		Table("permission_catalog").
		Where("product = ?", product).
		Order("group_name, sort_order, key")
	if !includeInactive {
		q = q.Where("is_active")
	}
	if err := q.Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("repository: list catalogue: %w", err)
	}

	out := make([]CatalogEntry, 0, len(rows))
	for _, row := range rows {
		e := CatalogEntry{
			Key:          row.Key,
			Product:      row.Product,
			Feature:      row.Feature,
			Group:        row.GroupName,
			Label:        row.Label,
			DefaultLabel: row.Label,
			SortOrder:    row.SortOrder,
			IsActive:     row.IsActive,
		}
		if row.LabelOverride != nil && *row.LabelOverride != "" {
			e.Label = *row.LabelOverride
			e.IsOverridden = true
		}
		out = append(out, e)
	}
	return out, nil
}

// SetLabel overrides the wording of one key, or clears the override when the
// label is empty.
//
// It cannot create a key, change what a key gates, or activate a retired one.
// Presentation is the only thing editable here, which is what keeps "a key
// exists" a statement about the code.
func (r *CatalogRepository) SetLabel(ctx context.Context, product, key, label string) error {
	var value interface{}
	if label != "" {
		value = label
	}
	res := r.db.WithContext(ctx).Exec(`
		UPDATE permission_catalog
		SET label_override = ?, updated_at = NOW()
		WHERE product = ? AND key = ?
	`, value, product, key)
	if res.Error != nil {
		return fmt.Errorf("repository: set catalogue label: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
