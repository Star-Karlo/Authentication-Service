package query

import (
	"testing"
)

var testFields = FieldSet{
	"orderNumber": "order_number",
	"statusCode":  "status_code",
	"createdAt":   "created_at",
}

// TestParseRejectsFieldsOutsideTheAllowlist is the security case, not a
// convenience one. A field name that reaches an ORDER BY or a Mongo filter key
// unchecked lets a caller sort by a column they cannot read, probe fields that
// are not part of the API, or inject SQL.
//
// A disallowed field REFUSES the whole request rather than being dropped from
// it. Dropping is the tempting behaviour and it is wrong twice over: the caller
// asked to narrow a list and silently got the unnarrowed one, which reads as a
// filter that does not work; and a probe for `password_hash` returns 200,
// telling the prober only that nothing happened rather than that the field is
// not addressable.
func TestParseRejectsFieldsOutsideTheAllowlist(t *testing.T) {
	p := Parse("0", "20",
		`[{"id":"password_hash","value":"x"},{"id":"orderNumber","value":"ORD-1"}]`,
		"", "", testFields)

	if p.Err == nil {
		t.Fatalf("a disallowed filter field was accepted: %+v", p.Filters)
	}
	if len(p.Filters) != 0 {
		t.Errorf("a refused request should carry no filters, got %+v", p.Filters)
	}

	// The same rule on the sort side, checked separately: they are parsed by
	// different functions and one has been fixed without the other before.
	p = Parse("0", "20", "", `[{"id":"secret_column","desc":true}]`, "", testFields)
	if p.Err == nil {
		t.Fatalf("a disallowed sort field was accepted: %+v", p.Sorts)
	}
}

// The allowlisted names still resolve to their columns, which is the other half
// of the contract — a rule that refused everything would also pass the test
// above.
func TestParseMapsAllowlistedFieldsToColumns(t *testing.T) {
	p := Parse("0", "20",
		`[{"id":"orderNumber","value":"ORD-1"}]`,
		`[{"id":"createdAt","desc":true}]`,
		"", testFields)

	if p.Err != nil {
		t.Fatalf("an allowlisted request was refused: %v", p.Err)
	}
	if len(p.Filters) != 1 || p.Filters[0].Field != "order_number" {
		t.Errorf("filters = %+v, want one on order_number", p.Filters)
	}
	if len(p.Sorts) != 1 || p.Sorts[0].Field != "created_at" {
		t.Errorf("sorts = %+v, want one on created_at", p.Sorts)
	}
}

// TestParseRejectsInjectionAttempts: even if an attacker guesses a real column
// name, an expression is not a field name and must not survive the allowlist.
func TestParseRejectsInjectionAttempts(t *testing.T) {
	hostile := []string{
		"order_number; DROP TABLE orders",
		"order_number--",
		"1=1",
		"(SELECT password_hash FROM users)",
		"order_number' OR '1'='1",
		"$where",
		"__proto__",
	}

	for _, name := range hostile {
		p := Parse("0", "20",
			`[{"id":`+quote(name)+`,"value":"x"}]`,
			`[{"id":`+quote(name)+`,"desc":true}]`,
			"", testFields)

		if len(p.Filters) != 0 {
			t.Errorf("hostile filter %q survived: %+v", name, p.Filters)
		}
		if len(p.Sorts) != 0 {
			t.Errorf("hostile sort %q survived: %+v", name, p.Sorts)
		}
	}
}

func quote(s string) string {
	out := []rune{'"'}
	for _, r := range s {
		if r == '"' || r == '\\' {
			out = append(out, '\\')
		}
		out = append(out, r)
	}
	return string(append(out, '"'))
}

// TestPageSizeIsClamped: without a ceiling, ?pageSize=1000000 is a denial of
// service against the database dressed up as a normal request.
func TestPageSizeIsClamped(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", DefaultPageSize},
		{"0", DefaultPageSize},
		{"-5", DefaultPageSize},
		{"nonsense", DefaultPageSize},
		{"20", 20},
		{"200", MaxPageSize},
		{"1000000", MaxPageSize},
	}

	for _, tc := range cases {
		p := Parse("0", tc.in, "", "", "", testFields)
		if p.PageSize != tc.want {
			t.Errorf("pageSize %q = %d, want %d", tc.in, p.PageSize, tc.want)
		}
	}
}

func TestNegativePageIsClamped(t *testing.T) {
	if p := Parse("-3", "20", "", "", "", testFields); p.Page != 0 {
		t.Errorf("page = %d, want 0", p.Page)
	}
	if p := Parse("nonsense", "20", "", "", "", testFields); p.Page != 0 {
		t.Errorf("page = %d, want 0", p.Page)
	}
}

// TestMalformedJSONIsIgnoredNotFatal: the legacy clients send these parameters
// from stored bookmarks, and rejecting a whole request because one carries a
// stale filter is worse than ignoring it.
func TestMalformedJSONIsIgnored(t *testing.T) {
	p := Parse("0", "20", "{not json", "[[[", "", testFields)

	if len(p.Filters) != 0 || len(p.Sorts) != 0 {
		t.Errorf("malformed input produced clauses: %+v %+v", p.Filters, p.Sorts)
	}
	if p.PageSize != 20 {
		t.Errorf("the rest of the request should still parse, pageSize = %d", p.PageSize)
	}
}

func TestOffsetAndTotalPages(t *testing.T) {
	p := Params{Page: 0, PageSize: 20}
	if p.Offset() != 0 {
		t.Errorf("Offset() on page 0 = %d, want 0", p.Offset())
	}

	p.Page = 3
	if p.Offset() != 60 {
		t.Errorf("Offset() on page 3 = %d, want 60", p.Offset())
	}

	cases := []struct {
		total int64
		want  int
	}{
		{0, 0},
		{1, 1},
		{20, 1},
		{21, 2},
		{40, 2},
		{41, 3},
	}
	p = Params{PageSize: 20}
	for _, tc := range cases {
		if got := p.TotalPages(tc.total); got != tc.want {
			t.Errorf("TotalPages(%d) = %d, want %d", tc.total, got, tc.want)
		}
	}

	// A zero page size must not divide by zero.
	zero := Params{PageSize: 0}
	if got := zero.TotalPages(10); got != 0 {
		t.Errorf("TotalPages with no page size = %d, want 0", got)
	}
}

func TestOperatorNormalisation(t *testing.T) {
	cases := map[string]Operator{
		"":         OpEq,
		"eq":       OpEq,
		"neq":      OpNeq,
		"ne":       OpNeq,
		"!=":       OpNeq,
		"like":     OpLike,
		"contains": OpLike,
		"in":       OpIn,
		"gt":       OpGt,
		">":        OpGt,
		"gte":      OpGte,
		">=":       OpGte,
		"lt":       OpLt,
		"lte":      OpLte,
		"between":  OpBetween,

		// Spellings clients actually send meaning "contains". They were
		// becoming equality, so a text search returned zero rows and read as
		// "no data".
		"regex": OpLike,
		"match": OpLike,
	}

	for in, want := range cases {
		if got := normaliseOperator(in); got != want {
			t.Errorf("normaliseOperator(%q) = %q, want %q", in, got, want)
		}
	}

	// An operator the server does not implement is marked unknown so
	// parseFilters can refuse it. Mapping it to equality — the old behaviour —
	// returned zero rows and looked like an empty result set rather than a bad
	// request.
	if got := normaliseOperator("nonsense"); got != opUnknown {
		t.Errorf("normaliseOperator(\"nonsense\") = %q, want it marked unknown", got)
	}
	if p := Parse("0", "20", `[{"id":"orderNumber","value":"x","operator":"nonsense"}]`, "", "", testFields); p.Err == nil {
		t.Error("a filter with an unimplemented operator should be refused, not treated as equality")
	}
}

func TestFieldSetResolve(t *testing.T) {
	col, ok := testFields.Resolve("orderNumber")
	if !ok || col != "order_number" {
		t.Errorf("Resolve = %q, %v", col, ok)
	}

	if _, ok := testFields.Resolve("unknown"); ok {
		t.Error("an unknown field should not resolve")
	}

	// A nil field set must deny everything, not allow everything: a repository
	// that forgets to declare its allowlist should lose functionality, not
	// gain an open query surface.
	var nilSet FieldSet
	if _, ok := nilSet.Resolve("anything"); ok {
		t.Error("a nil FieldSet must resolve nothing")
	}
}

func TestPageInfoClampsCounts(t *testing.T) {
	p := Params{Page: 2, PageSize: 20}
	info := p.PageInfo(45)

	if info.GetPage() != 2 || info.GetPageSize() != 20 {
		t.Errorf("page info = %+v", info)
	}
	if info.GetTotalRows() != 45 {
		t.Errorf("totalRows = %d, want 45", info.GetTotalRows())
	}
	if info.GetTotalPages() != 3 {
		t.Errorf("totalPages = %d, want 3", info.GetTotalPages())
	}
}
