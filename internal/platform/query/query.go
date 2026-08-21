// Package query normalises the listing parameters the legacy REST API accepts,
// so every service pages, filters and sorts the same way.
//
// The legacy front ends send react-table style parameters:
//
//	?page=0&pageSize=20&filtered=[{"id":"status","value":"draft"}]&sorted=[{"id":"createdAt","desc":true}]
//
// Those are preserved rather than modernised, because changing them would mean
// changing every client at the same time as splitting the backend.
package query

import (
	"encoding/json"
	"strconv"
	"strings"

	commonv1 "github.com/karlo/authentication-service/internal/platform/genproto/karlo/common/v1"
	"github.com/karlo/authentication-service/internal/platform/safeconv"
)

// MaxPageSize caps a listing. Without it, `?pageSize=1000000` is a denial of
// service against the database.
const MaxPageSize = 200

// DefaultPageSize matches the legacy default.
const DefaultPageSize = 20

// Filter is one normalised filter clause.
type Filter struct {
	Field    string
	Value    string
	Operator Operator
}

// Operator enumerates the comparisons a filter may use.
type Operator string

const (
	OpEq      Operator = "eq"
	OpNeq     Operator = "neq"
	OpLike    Operator = "like"
	OpIn      Operator = "in"
	OpGt      Operator = "gt"
	OpGte     Operator = "gte"
	OpLt      Operator = "lt"
	OpLte     Operator = "lte"
	OpBetween Operator = "between"
)

// Sort is one normalised sort clause.
type Sort struct {
	Field string
	Desc  bool
}

// Params is the normalised listing request.
type Params struct {
	Page     int
	PageSize int
	Filters  []Filter
	Sorts    []Sort
	Search   string
}

// Offset is the row offset for the requested page. Pages are zero-based, as in
// the legacy API.
func (p Params) Offset() int {
	if p.Page < 1 {
		return 0
	}
	return p.Page * p.PageSize
}

// TotalPages computes the page count for a row total.
func (p Params) TotalPages(total int64) int {
	if p.PageSize <= 0 {
		return 0
	}
	pages := int(total) / p.PageSize
	if int(total)%p.PageSize != 0 {
		pages++
	}
	return pages
}

// Parse builds Params from raw query-string values, clamping the page size and
// ignoring malformed filter or sort JSON rather than failing the request. The
// legacy clients send both, and rejecting a request because a stale bookmark
// carries a bad filter is worse than ignoring it.
func Parse(pageStr, pageSizeStr, filteredJSON, sortedJSON, search string, allowed FieldSet) Params {
	page, _ := strconv.Atoi(pageStr)
	if page < 0 {
		page = 0
	}

	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil || pageSize <= 0 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}

	return Params{
		Page:     page,
		PageSize: pageSize,
		Filters:  parseFilters(filteredJSON, allowed),
		Sorts:    parseSorts(sortedJSON, allowed),
		Search:   strings.TrimSpace(search),
	}
}

// FieldSet is the allowlist of fields a caller may filter or sort by.
//
// This is a security boundary, not a convenience. Passing a client-supplied
// string straight into an ORDER BY or a Mongo filter key lets a caller sort by
// a column they cannot read, or probe fields that are not part of the API.
type FieldSet map[string]string

// Resolve maps an external field name to its storage column, reporting whether
// the field is allowed at all.
func (f FieldSet) Resolve(name string) (string, bool) {
	if f == nil {
		return "", false
	}
	col, ok := f[name]
	return col, ok
}

type rawFilter struct {
	ID       string `json:"id"`
	Value    string `json:"value"`
	Operator string `json:"operator"`
}

type rawSort struct {
	ID   string `json:"id"`
	Desc bool   `json:"desc"`
}

func parseFilters(raw string, allowed FieldSet) []Filter {
	if raw == "" {
		return nil
	}
	var items []rawFilter
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return nil
	}

	out := make([]Filter, 0, len(items))
	for _, it := range items {
		col, ok := allowed.Resolve(it.ID)
		if !ok {
			continue
		}
		out = append(out, Filter{
			Field:    col,
			Value:    it.Value,
			Operator: normaliseOperator(it.Operator),
		})
	}
	return out
}

func parseSorts(raw string, allowed FieldSet) []Sort {
	if raw == "" {
		return nil
	}
	var items []rawSort
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return nil
	}

	out := make([]Sort, 0, len(items))
	for _, it := range items {
		col, ok := allowed.Resolve(it.ID)
		if !ok {
			continue
		}
		out = append(out, Sort{Field: col, Desc: it.Desc})
	}
	return out
}

func normaliseOperator(s string) Operator {
	switch strings.ToLower(s) {
	case "neq", "ne", "!=":
		return OpNeq
	case "like", "contains":
		return OpLike
	case "in":
		return OpIn
	case "gt", ">":
		return OpGt
	case "gte", ">=":
		return OpGte
	case "lt", "<":
		return OpLt
	case "lte", "<=":
		return OpLte
	case "between":
		return OpBetween
	default:
		return OpEq
	}
}

// FromProto converts a gRPC Query into Params, applying the same allowlist and
// clamping as the HTTP path.
func FromProto(q *commonv1.Query, allowed FieldSet) Params {
	p := Params{Page: 0, PageSize: DefaultPageSize}
	if q == nil {
		return p
	}

	if q.GetPage() != nil {
		p.Page = int(q.GetPage().GetPage())
		if p.Page < 0 {
			p.Page = 0
		}
		if size := int(q.GetPage().GetPageSize()); size > 0 {
			p.PageSize = min(size, MaxPageSize)
		}
	}

	for _, f := range q.GetFiltered() {
		col, ok := allowed.Resolve(f.GetId())
		if !ok {
			continue
		}
		p.Filters = append(p.Filters, Filter{
			Field:    col,
			Value:    f.GetValue(),
			Operator: operatorFromProto(f.GetOperator()),
		})
	}

	for _, s := range q.GetSorted() {
		col, ok := allowed.Resolve(s.GetId())
		if !ok {
			continue
		}
		p.Sorts = append(p.Sorts, Sort{Field: col, Desc: s.GetDesc()})
	}

	p.Search = strings.TrimSpace(q.GetSearch())
	return p
}

// PageInfo builds the gRPC pagination response block.
//
// The counts are clamped rather than converted directly: a plain int32()
// conversion wraps silently, so a page count past the int32 ceiling would
// surface to a client as a negative number of pages.
func (p Params) PageInfo(total int64) *commonv1.PageInfo {
	return &commonv1.PageInfo{
		Page:       safeconv.NonNegativeInt32(p.Page),
		PageSize:   safeconv.NonNegativeInt32(p.PageSize),
		TotalRows:  total,
		TotalPages: safeconv.NonNegativeInt32(p.TotalPages(total)),
	}
}

func operatorFromProto(op commonv1.Operator) Operator {
	switch op {
	case commonv1.Operator_OPERATOR_NEQ:
		return OpNeq
	case commonv1.Operator_OPERATOR_LIKE:
		return OpLike
	case commonv1.Operator_OPERATOR_IN:
		return OpIn
	case commonv1.Operator_OPERATOR_GT:
		return OpGt
	case commonv1.Operator_OPERATOR_GTE:
		return OpGte
	case commonv1.Operator_OPERATOR_LT:
		return OpLt
	case commonv1.Operator_OPERATOR_LTE:
		return OpLte
	case commonv1.Operator_OPERATOR_BETWEEN:
		return OpBetween
	default:
		return OpEq
	}
}
