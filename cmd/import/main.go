// Command import loads the legacy user collection into the authentication
// database.
//
// The legacy system had ONE table. A `users` document carried the person, the
// company they belonged to, that company's commercial settings, and their
// permissions, all flattened together — 195 columns in the export. This
// service separates those into companies, users, per-product access and
// entitlement, so the import is a decomposition rather than a copy.
//
// The rules, and why each exists:
//
//   - A company is derived from every user with NO parent. `type` looks like
//     the right discriminator and is not: 11,578 rows are typed `mainAccount`
//     AND have a parent, because the field was repurposed as a free-text job
//     title. `parent` is the only reliable signal.
//
//   - Duplicate identifiers are resolved rather than refused. The export has
//     89 extra rows sharing an email, 115 sharing a username and 1,536 sharing
//     a phone. The unique indexes are partial — they ignore NULL — so the
//     oldest account keeps the identifier and the others have it cleared. The
//     alternative is dropping real accounts.
//
//   - Everything is keyed on `legacy_id`, so a re-run updates rather than
//     duplicates and a partial run can be resumed.
//
// It is a DRY RUN unless -confirm is passed, and it refuses a database that
// does not look local unless -allow-remote is given as well.
//
//	go run ./cmd/import -file ../../Data_RAW/prod.users.csv
//	go run ./cmd/import -file ../../Data_RAW/prod.users.csv -confirm
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func main() {
	var (
		file        = flag.String("file", "", "path to prod.users.csv")
		dsn         = flag.String("dsn", envOr("MIGRATE_URL", "postgres://karlo:karlo@localhost:5432/karlo_auth?sslmode=disable"), "target database")
		confirm     = flag.Bool("confirm", false, "actually write; without this it is a dry run")
		allowRemote = flag.Bool("allow-remote", false, "permit a target that does not look local")
		limit       = flag.Int("limit", 0, "stop after N rows, for a smoke test")
	)
	flag.Parse()

	if *file == "" {
		fail("-file is required")
	}
	if !*allowRemote && !looksLocal(*dsn) {
		fail("the target does not look local and -allow-remote was not given:\n  %s\n"+
			"This writes 25,000 real accounts. Point it deliberately.", redact(*dsn))
	}

	rows, err := readCSV(*file, *limit)
	if err != nil {
		fail("reading %s: %v", *file, err)
	}
	fmt.Printf("read %d rows from %s\n\n", len(rows), *file)

	plan, err := build(rows)
	if err != nil {
		fail("building the plan: %v", err)
	}
	plan.report()

	if !*confirm {
		fmt.Println("\nDRY RUN — nothing was written. Re-run with -confirm to apply.")
		return
	}

	db, err := gorm.Open(postgres.Open(*dsn), &gorm.Config{
		Logger:  logger.Default.LogMode(logger.Silent),
		NowFunc: func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		fail("connecting: %v", err)
	}

	if err := plan.apply(db); err != nil {
		fail("applying: %v", err)
	}
	fmt.Println("\nDone.")
}

// row is one legacy user, with the columns this import reads.
type row map[string]string

func (r row) get(key string) string { return sanitise(r[key]) }

func (r row) boolean(key string) bool {
	v := strings.ToLower(r.get(key))
	return v == "true" || v == "1"
}

func (r row) time(key string) *time.Time {
	raw := r.get(key)
	if raw == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, raw); err == nil {
			u := t.UTC()
			return &u
		}
	}
	return nil
}

func (r row) number(key string) *float64 {
	raw := r.get(key)
	if raw == "" {
		return nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return nil
	}
	return &f
}

func readCSV(path string, limit int) ([]row, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true

	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("reading the header: %w", err)
	}
	for i := range header {
		header[i] = strings.TrimSpace(header[i])
	}

	var out []row
	for {
		rec, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		r := make(row, len(header))
		for i, name := range header {
			if i < len(rec) {
				r[name] = rec[i]
			}
		}
		out = append(out, r)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func looksLocal(dsn string) bool {
	return strings.Contains(dsn, "localhost") ||
		strings.Contains(dsn, "127.0.0.1") ||
		strings.Contains(dsn, "postgres-auth")
}

func redact(dsn string) string {
	if at := strings.LastIndex(dsn, "@"); at != -1 {
		if scheme := strings.Index(dsn, "://"); scheme != -1 && scheme+3 < at {
			return dsn[:scheme+3] + "***" + dsn[at:]
		}
	}
	return dsn
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "import: "+format+"\n", args...)
	os.Exit(1)
}

func jsonOf(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var _ = uuid.New
