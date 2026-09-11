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
	"fmt"
	"sort"
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

	// Values carries every value for an operator that takes a list. Value
	// holds the first, so a caller that only understands scalars still works.
	Values []string
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
	// Err is set when the request could not be understood — an unknown filter
	// field, a malformed list. Handlers must check it and answer 400: a filter
	// that is quietly ignored turns a filtered list into an unfiltered one,
	// which returns 200 with real rows and only the wrong count.
	Err error

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

	filters, err := parseFilters(filteredJSON, allowed)
	if err != nil {
		// Recorded rather than returned, so the existing signature holds. The
		// handler checks Err and answers 400; a caller that forgets still gets
		// an EMPTY filter list rather than an unfiltered one, which fails
		// closed — no rows instead of every row.
		return Params{Page: page, PageSize: pageSize, Err: err,
			Search: strings.TrimSpace(search)}
	}

	sorts, err := parseSorts(sortedJSON, allowed)
	if err != nil {
		// Refused for the same reason a bad filter is, and it was previously
		// dropped instead. A caller who asked to sort by a field the server
		// does not offer got an arbitrary order back with nothing to say so —
		// which reads as "sorting is broken" rather than "that field is not
		// sortable", and hides a probe for column names behind a 200.
		return Params{Page: page, PageSize: pageSize, Err: err,
			Search: strings.TrimSpace(search)}
	}

	return Params{
		Page:     page,
		PageSize: pageSize,
		Filters:  filters,
		Sorts:    sorts,
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

// Names lists the filterable fields, so an error can say what IS allowed
// rather than only what is not.
func (f FieldSet) Names() []string {
	out := make([]string, 0, len(f))
	for name := range f {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

type rawFilter struct {
	ID       string      `json:"id"`
	Value    filterValue `json:"value"`
	Operator string      `json:"operator"`
	// Type is the spelling the legacy clients use for the operator. Accepted
	// alongside `operator` because both are in the wild.
	Type string `json:"type"`
}

// filterValue accepts either a scalar or an array.
//
// Clients send both, and they used to be handled by neither. A `string` field
// made `["draft","submitted"]` fail to unmarshal, which aborted the WHOLE
// filter list and returned every row — a broken filter that looks like a
// working one whenever the unfiltered result happens to be small. Meanwhile
// "draft,submitted" parsed fine and became a single value, so `IN
// ('draft,submitted')` matched nothing and looked like "no data".
//
// Both shapes are now understood, and a comma-separated string is split for
// the operators that take a list.
type filterValue struct {
	values []string
}

func (v *filterValue) UnmarshalJSON(b []byte) error {
	var single interface{}
	if err := json.Unmarshal(b, &single); err == nil {
		switch t := single.(type) {
		case string:
			v.values = []string{t}
			return nil
		case float64:
			v.values = []string{strconv.FormatFloat(t, 'f', -1, 64)}
			return nil
		case bool:
			v.values = []string{strconv.FormatBool(t)}
			return nil
		case nil:
			v.values = nil
			return nil
		}
	}

	var list []interface{}
	if err := json.Unmarshal(b, &list); err != nil {
		return fmt.Errorf("query: a filter value must be a scalar or an array, got %s", b)
	}
	for _, item := range list {
		switch t := item.(type) {
		case string:
			v.values = append(v.values, t)
		case float64:
			v.values = append(v.values, strconv.FormatFloat(t, 'f', -1, 64))
		case bool:
			v.values = append(v.values, strconv.FormatBool(t))
		}
	}
	return nil
}

// scalar renders the value for a single-value comparison.
func (v filterValue) scalar() string {
	if len(v.values) == 0 {
		return ""
	}
	return v.values[0]
}

// list renders the value for an operator that takes several, splitting a
// comma-separated scalar so both client spellings work.
func (v filterValue) list() []string {
	if len(v.values) == 1 && strings.Contains(v.values[0], ",") {
		parts := strings.Split(v.values[0], ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	}
	return v.values
}

type rawSort struct {
	ID   string `json:"id"`
	Desc bool   `json:"desc"`
}

// parseFilters turns the client's JSON into normalised clauses, returning an
// error rather than silently dropping what it does not understand.
//
// Silently dropping is how a filtered list becomes an unfiltered one: the
// response is 200, the rows are real, and only the count is wrong. That is far
// harder to notice than a 400, and it was doing exactly this for every array
// value and every unknown field.
func parseFilters(raw string, allowed FieldSet) ([]Filter, error) {
	if raw == "" {
		return nil, nil
	}
	var items []rawFilter
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return nil, fmt.Errorf("query: `filtered` is not a valid filter list: %w", err)
	}

	out := make([]Filter, 0, len(items))
	for _, it := range items {
		col, ok := allowed.Resolve(it.ID)
		if !ok {
			return nil, fmt.Errorf("query: %q cannot be filtered on (allowed: %s)",
				it.ID, strings.Join(allowed.Names(), ", "))
		}

		op := normaliseOperator(firstNonEmpty(it.Operator, it.Type))
		if op == opUnknown {
			return nil, fmt.Errorf("query: %q is not a filter operator on %q "+
				"(eq, neq, like, in, gt, gte, lt, lte, between)",
				firstNonEmpty(it.Operator, it.Type), it.ID)
		}
		values := it.Value.list()
		if op == OpIn && len(values) == 0 {
			return nil, fmt.Errorf("query: an `in` filter on %q needs at least one value", it.ID)
		}

		out = append(out, Filter{
			Field:    col,
			Value:    it.Value.scalar(),
			Values:   values,
			Operator: op,
		})
	}
	return out, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func parseSorts(raw string, allowed FieldSet) ([]Sort, error) {
	if raw == "" {
		return nil, nil
	}
	var items []rawSort
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return nil, fmt.Errorf("query: `sorted` is not a valid sort list: %w", err)
	}

	out := make([]Sort, 0, len(items))
	for _, it := range items {
		col, ok := allowed.Resolve(it.ID)
		if !ok {
			return nil, fmt.Errorf("query: %q cannot be sorted on (allowed: %s)",
				it.ID, strings.Join(allowed.Names(), ", "))
		}
		out = append(out, Sort{Field: col, Desc: it.Desc})
	}
	return out, nil
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
	case "regex", "match":
		// Clients send these meaning "contains". Mapping them to LIKE rather
		// than refusing them: they were silently becoming equality, so a text
		// search returned zero rows and read as "no data". Accepting the
		// spelling costs nothing and matches what the caller meant.
		return OpLike
	case "", "eq", "equal", "equals", "=", "==", "is":
		return OpEq
	default:
		return opUnknown
	}
}

// opUnknown marks an operator the server does not implement, so parseFilters
// can refuse it rather than quietly comparing for equality — which returned
// zero rows and looked like an empty result set instead of a bad request.
const opUnknown Operator = "?"

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
