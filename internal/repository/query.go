package repository

import (
	"fmt"
	"strings"

	"github.com/karlo/authentication-service/internal/platform/query"
	"gorm.io/gorm"
)

// applyFilters translates normalised filters into a GORM where chain.
//
// Field names arriving here have already passed the repository's allowlist, so
// they are safe to interpolate into the column position. Values are always
// bound as parameters and never interpolated.
func applyFilters(q *gorm.DB, p query.Params) *gorm.DB {
	for _, f := range p.Filters {
		col := quoteIdent(f.Field)
		switch f.Operator {
		case query.OpNeq:
			q = q.Where(col+" <> ?", f.Value)
		case query.OpLike:
			q = q.Where(col+" ILIKE ?", "%"+f.Value+"%")
		case query.OpIn:
			q = q.Where(col+" IN ?", strings.Split(f.Value, ","))
		case query.OpGt:
			q = q.Where(col+" > ?", f.Value)
		case query.OpGte:
			q = q.Where(col+" >= ?", f.Value)
		case query.OpLt:
			q = q.Where(col+" < ?", f.Value)
		case query.OpLte:
			q = q.Where(col+" <= ?", f.Value)
		case query.OpBetween:
			bounds := strings.SplitN(f.Value, ",", 2)
			if len(bounds) == 2 {
				q = q.Where(col+" BETWEEN ? AND ?", bounds[0], bounds[1])
			}
		default:
			q = q.Where(col+" = ?", f.Value)
		}
	}
	return q
}

// applySorts translates normalised sorts into an ORDER BY, falling back to the
// given default when the caller asked for none.
func applySorts(q *gorm.DB, p query.Params, fallback string) *gorm.DB {
	if len(p.Sorts) == 0 {
		return q.Order(fallback)
	}
	for _, s := range p.Sorts {
		dir := "ASC"
		if s.Desc {
			dir = "DESC"
		}
		q = q.Order(quoteIdent(s.Field) + " " + dir)
	}
	return q
}

// quoteIdent double-quotes an identifier. Combined with the allowlist this is
// belt and braces, but it means a future careless addition to a FieldSet cannot
// become an injection.
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// isUniqueViolation reports whether an error is a Postgres 23505.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "23505") || strings.Contains(msg, "duplicate key value")
}

var _ = fmt.Sprintf
