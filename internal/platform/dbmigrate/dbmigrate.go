// Package dbmigrate brings the database up to the current schema.
//
// Run as `server migrate` from the same image that serves traffic, so a
// migration executes inside the VPC with the same credentials as the service —
// RDS is not reachable from anywhere else, and a separate migration image would
// be one more thing to keep in step with the SQL it ships.
//
// It creates the database first if it is absent. RDS provisions only the
// default `postgres` database; the service's own has to be made, and asking a
// person to do it by hand is how a fresh environment fails on its first
// request with "database does not exist".
package dbmigrate

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
)

// Run applies every pending migration under dir. Safe to run repeatedly: an
// already-current database is a no-op, which is what lets it sit in a deploy
// pipeline without a "has this been done yet" check.
func Run(dsn, dbName, dir string) error {
	if err := ensureDatabase(dsn, dbName); err != nil {
		return err
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("migrate: open: %w", err)
	}
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("migrate: driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance("file://"+dir, "postgres", driver)
	if err != nil {
		return fmt.Errorf("migrate: source %s: %w", dir, err)
	}

	before, _, _ := m.Version()
	err = m.Up()
	switch {
	case errors.Is(err, migrate.ErrNoChange):
		slog.Info("database already current", "version", before)
		return nil
	case err != nil:
		return fmt.Errorf("migrate: up: %w", err)
	}
	after, _, _ := m.Version()
	slog.Info("migrated", "from", before, "to", after)
	return nil
}

// ensureDatabase creates dbName if it does not exist.
//
// Connects to the maintenance database, because a connection needs SOME
// database to attach to and the one being created is by definition absent.
// Postgres has no CREATE DATABASE IF NOT EXISTS, hence the lookup first.
func ensureDatabase(dsn, dbName string) error {
	maint := strings.Replace(dsn, "dbname="+dbName, "dbname=postgres", 1)
	db, err := sql.Open("postgres", maint)
	if err != nil {
		return fmt.Errorf("migrate: open maintenance db: %w", err)
	}
	defer db.Close()

	var exists bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, dbName).Scan(&exists); err != nil {
		return fmt.Errorf("migrate: checking for %s: %w", dbName, err)
	}
	if exists {
		return nil
	}
	// The name comes from configuration, never a request, but it is quoted
	// regardless: an identifier is not a parameter and cannot be bound.
	if _, err := db.Exec(`CREATE DATABASE "` + strings.ReplaceAll(dbName, `"`, `""`) + `"`); err != nil {
		return fmt.Errorf("migrate: creating %s: %w", dbName, err)
	}
	slog.Info("created database", "name", dbName)
	return nil
}
