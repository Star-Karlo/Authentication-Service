// Package coldstore writes rows as Parquet into S3 Glacier Deep Archive.
//
// The shared half of every service's cold storage: the business service
// archives whole aggregates with it, the authentication service its audit
// log, the notification service its message history. What differs per
// service is which rows and when; what is the same is the file — Parquet,
// zstd, one file per table per day under a Hive partition
// (<prefix>/<table>/dt=YYYY-MM-DD/<run>.parquet), typed the same way so
// Athena or DuckDB can read all of them with one convention.
//
// Column typing is deliberately narrow: booleans, 64-bit integers and
// doubles as themselves, everything else as a string — uuids, timestamps
// (RFC 3339 with nanoseconds), numerics as decimal text, JSON as its text.
// A string casts back into any of those; a float that rounded an amount
// would not.
package coldstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/parquet-go/parquet-go"
)

// Kind is a column's Parquet type.
type Kind int

const (
	String Kind = iota
	Bool
	Int
	Double
)

// KindOfPostgres maps an information_schema data_type onto a Kind.
func KindOfPostgres(dataType string) Kind {
	switch dataType {
	case "boolean":
		return Bool
	case "smallint", "integer", "bigint":
		return Int
	case "real", "double precision":
		return Double
	default:
		return String
	}
}

// KindOfValue infers a Kind from a Go value, for stores without a schema
// (Mongo). Nil is unknown and yields String, the type everything casts to.
func KindOfValue(v any) Kind {
	switch v.(type) {
	case bool:
		return Bool
	case int, int8, int16, int32, int64, uint8, uint16, uint32:
		return Int
	case float32, float64:
		return Double
	default:
		return String
	}
}

// Schema is the column set of one table's files.
type Schema struct {
	names []string
	kinds map[string]Kind
	pq    *parquet.Schema
}

// NewSchema builds a schema from column kinds. Every column is optional.
func NewSchema(table string, kinds map[string]Kind) *Schema {
	group := parquet.Group{}
	for name, k := range kinds {
		var node parquet.Node
		switch k {
		case Bool:
			node = parquet.Optional(parquet.Leaf(parquet.BooleanType))
		case Int:
			node = parquet.Optional(parquet.Int(64))
		case Double:
			node = parquet.Optional(parquet.Leaf(parquet.DoubleType))
		default:
			node = parquet.Optional(parquet.String())
		}
		group[name] = node
	}
	s := parquet.NewSchema(table, group)
	names := make([]string, 0, len(s.Columns()))
	for _, path := range s.Columns() {
		names = append(names, path[0])
	}
	return &Schema{names: names, kinds: kinds, pq: s}
}

// Columns lists the schema's columns in file order.
func (s *Schema) Columns() []string { return s.names }

// Encode writes rows as one Parquet file. Values are coerced to their
// column's kind; a column absent from a row is null.
func (s *Schema) Encode(rows []map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	w := parquet.NewWriter(&buf, s.pq, parquet.Compression(&parquet.Zstd))
	batch := make([]parquet.Row, 0, 256)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		_, err := w.WriteRows(batch)
		batch = batch[:0]
		return err
	}
	for _, m := range rows {
		row := make(parquet.Row, 0, len(s.names))
		for i, name := range s.names {
			v, err := Coerce(m[name], s.kinds[name])
			if err != nil {
				return nil, fmt.Errorf("column %s: %w", name, err)
			}
			if v == nil {
				row = append(row, parquet.NullValue().Level(0, 0, i))
			} else {
				row = append(row, parquet.ValueOf(v).Level(0, 1, i))
			}
		}
		batch = append(batch, row)
		if len(batch) == cap(batch) {
			if err := flush(); err != nil {
				return nil, err
			}
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Coerce turns a stored value into the Go value the column's Parquet type
// accepts, or nil for null.
func Coerce(v any, k Kind) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch k {
	case Bool:
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("expected bool, got %T", v)
		}
		return b, nil
	case Int:
		switch n := v.(type) {
		case int64:
			return n, nil
		case int32:
			return int64(n), nil
		case int:
			return int64(n), nil
		case int16:
			return int64(n), nil
		case int8:
			return int64(n), nil
		case uint8:
			return int64(n), nil
		case uint16:
			return int64(n), nil
		case uint32:
			return int64(n), nil
		}
		return nil, fmt.Errorf("expected integer, got %T", v)
	case Double:
		switch f := v.(type) {
		case float64:
			return f, nil
		case float32:
			return float64(f), nil
		}
		return nil, fmt.Errorf("expected float, got %T", v)
	default:
		switch s := v.(type) {
		case string:
			return s, nil
		case []byte:
			return string(s), nil
		case time.Time:
			return s.UTC().Format(time.RFC3339Nano), nil
		case fmt.Stringer:
			return s.String(), nil
		case bool, int, int8, int16, int32, int64, uint8, uint16, uint32, float32, float64:
			return fmt.Sprint(v), nil
		default:
			// Maps, slices, structs: their JSON text.
			b, err := json.Marshal(v)
			if err != nil {
				return nil, err
			}
			return string(b), nil
		}
	}
}

// Key lays out a file path: <prefix>/<table>/dt=<day>/<run>.parquet.
func Key(prefix, table string, day time.Time, run string) string {
	return fmt.Sprintf("%s/%s/dt=%s/%s.parquet", prefix, table, day.UTC().Format("2006-01-02"), run)
}

// RunID names one run's files, sortable and unique to the second.
func RunID(now time.Time) string { return now.UTC().Format("20060102T150405Z") }

// SortedKeys is a helper for stable column discovery from maps.
func SortedKeys(m map[string]Kind) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Store writes objects into the cold storage class.
type Store interface {
	PutCold(ctx context.Context, key string, body []byte) (string, error)
}

// ErrNotConfigured is returned when no bucket is set.
var ErrNotConfigured = errors.New("coldstore: no bucket configured")

// S3 is the AWS implementation of Store.
type S3 struct {
	bucket string
	client *s3.Client
}

// NewS3 builds a store on the ambient credential chain (the task role in
// production). An empty bucket yields a store whose every call returns
// ErrNotConfigured, so a deployment without one still starts.
func NewS3(ctx context.Context, bucket, region string) (*S3, error) {
	if bucket == "" {
		return &S3{}, nil
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("coldstore: loading aws config: %w", err)
	}
	return &S3{bucket: bucket, client: s3.NewFromConfig(cfg)}, nil
}

func (s *S3) Configured() bool { return s != nil && s.bucket != "" }

// PutCold writes straight into Glacier Deep Archive and returns the class.
func (s *S3) PutCold(ctx context.Context, key string, body []byte) (string, error) {
	if !s.Configured() {
		return "", ErrNotConfigured
	}
	class := types.StorageClassDeepArchive
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:       aws.String(s.bucket),
		Key:          aws.String(key),
		Body:         bytes.NewReader(body),
		ContentType:  aws.String("application/vnd.apache.parquet"),
		StorageClass: class,
	})
	if err != nil {
		return "", fmt.Errorf("coldstore: put %s: %w", key, err)
	}
	return string(class), nil
}
