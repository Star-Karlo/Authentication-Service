// Package archive is the authentication service's cold storage.
//
// Two tables grow with every login and never stop:
//
//   - auth_audit_log: every sign-in, token, permission change. Read for a
//     few weeks (the rate limiter's fallback counts the last fifteen
//     minutes of it; support looks back days), kept for years as evidence.
//     Rows past the window go to S3 as Parquet, partitioned by the day
//     they happened, and are then deleted here. Nothing is lost: the file
//     is the record, queryable by date without a restore.
//   - sessions: one row per login, expired or revoked long ago. Nothing
//     needs a dead session; they are deleted, not archived.
package archive

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"gorm.io/gorm"

	"github.com/karlo/authentication-service/internal/platform/coldstore"
)

// Options control one run.
type Options struct {
	// AuditRetain is how long audit rows stay in Postgres.
	AuditRetain time.Duration
	// SessionRetain is how long expired or revoked sessions stay.
	SessionRetain time.Duration
	// Batch bounds the audit rows moved in one run.
	Batch int
	// KeepAuditRows writes the files but leaves the rows: a copy, not a move.
	KeepAuditRows bool
	DryRun        bool
	Prefix        string
}

type Archiver struct {
	db    *gorm.DB
	store coldstore.Store
	opts  Options
	now   func() time.Time
}

func New(db *gorm.DB, store coldstore.Store, opts Options) *Archiver {
	if opts.AuditRetain <= 0 {
		opts.AuditRetain = 30 * 24 * time.Hour
	}
	if opts.SessionRetain <= 0 {
		opts.SessionRetain = 30 * 24 * time.Hour
	}
	if opts.Batch <= 0 {
		opts.Batch = 100000
	}
	if opts.Prefix == "" {
		opts.Prefix = "archive"
	}
	return &Archiver{db: db, store: store, opts: opts, now: time.Now}
}

type Summary struct {
	AuditRows       int `json:"auditRows"`
	AuditFiles      int `json:"auditFiles"`
	Bytes           int `json:"bytes"`
	SessionsDeleted int `json:"sessionsDeleted"`
}

const auditTable = "auth_audit_log"

// Run moves cold audit rows out and purges dead sessions.
func (a *Archiver) Run(ctx context.Context) (Summary, error) {
	var sum Summary
	run := coldstore.RunID(a.now())

	// --- Audit log: one file per calendar day of created_at ---------------
	cutoff := a.now().Add(-a.opts.AuditRetain)
	var rows []map[string]any
	err := a.db.WithContext(ctx).Table(auditTable).
		Where("created_at < ?", cutoff).
		Order("created_at").
		Limit(a.opts.Batch).
		Find(&rows).Error
	if err != nil {
		return sum, fmt.Errorf("archive: reading %s: %w", auditTable, err)
	}
	slog.InfoContext(ctx, "audit rows past retention", "count", len(rows), "cutoff", cutoff, "dryRun", a.opts.DryRun)

	if len(rows) > 0 {
		schema, err := a.schemaFor(ctx, auditTable)
		if err != nil {
			return sum, err
		}
		// Group by day so a file holds one day of one table, whatever the
		// batch boundary. Days are in order because the rows are.
		var (
			day     time.Time
			dayRows []map[string]any
			maxID   int64
		)
		flush := func() error {
			if len(dayRows) == 0 {
				return nil
			}
			data, err := schema.Encode(dayRows)
			if err != nil {
				return fmt.Errorf("encoding %s: %w", auditTable, err)
			}
			key := coldstore.Key(a.opts.Prefix, auditTable, day, run)
			if a.opts.DryRun {
				slog.InfoContext(ctx, "would write", "key", key, "rows", len(dayRows), "bytes", len(data))
			} else {
				if _, err := a.store.PutCold(ctx, key, data); err != nil {
					return err
				}
				slog.InfoContext(ctx, "archive file written", "key", key, "rows", len(dayRows), "bytes", len(data))
				if !a.opts.KeepAuditRows {
					// Delete exactly what was written: this day's rows up to
					// the highest id in the file, never anything newer that
					// arrived while the file was being built.
					res := a.db.WithContext(ctx).Exec(
						`DELETE FROM `+auditTable+` WHERE id <= ? AND created_at >= ? AND created_at < ?`,
						maxID, day, day.Add(24*time.Hour))
					if res.Error != nil {
						return fmt.Errorf("deleting archived rows: %w", res.Error)
					}
				}
			}
			sum.AuditRows += len(dayRows)
			sum.AuditFiles++
			sum.Bytes += len(data)
			dayRows = dayRows[:0]
			maxID = 0
			return nil
		}
		for _, r := range rows {
			at, _ := r["created_at"].(time.Time)
			d := at.UTC().Truncate(24 * time.Hour)
			if !d.Equal(day) {
				if err := flush(); err != nil {
					return sum, err
				}
				day = d
			}
			dayRows = append(dayRows, r)
			if id, ok := r["id"].(int64); ok && id > maxID {
				maxID = id
			}
		}
		if err := flush(); err != nil {
			return sum, err
		}
	}

	// --- Sessions: dead for longer than the window are simply removed -----
	sessionCutoff := a.now().Add(-a.opts.SessionRetain)
	if a.opts.DryRun {
		var n int64
		a.db.WithContext(ctx).Table("sessions").
			Where("(revoked_at IS NOT NULL AND revoked_at < ?) OR expires_at < ?", sessionCutoff, sessionCutoff).
			Count(&n)
		sum.SessionsDeleted = int(n)
		slog.InfoContext(ctx, "would delete dead sessions", "count", n)
	} else {
		res := a.db.WithContext(ctx).Exec(
			`DELETE FROM sessions WHERE (revoked_at IS NOT NULL AND revoked_at < ?) OR expires_at < ?`,
			sessionCutoff, sessionCutoff)
		if res.Error != nil {
			return sum, fmt.Errorf("archive: deleting sessions: %w", res.Error)
		}
		sum.SessionsDeleted = int(res.RowsAffected)
		slog.InfoContext(ctx, "dead sessions deleted", "count", res.RowsAffected, "cutoff", sessionCutoff)
	}
	return sum, nil
}

func (a *Archiver) schemaFor(ctx context.Context, table string) (*coldstore.Schema, error) {
	var cols []struct {
		ColumnName string `gorm:"column:column_name"`
		DataType   string `gorm:"column:data_type"`
	}
	err := a.db.WithContext(ctx).Raw(`
		SELECT column_name, data_type FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = ?`, table).Scan(&cols).Error
	if err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("archive: table %q has no columns", table)
	}
	kinds := make(map[string]coldstore.Kind, len(cols))
	for _, c := range cols {
		kinds[c.ColumnName] = coldstore.KindOfPostgres(c.DataType)
	}
	return coldstore.NewSchema(table, kinds), nil
}
