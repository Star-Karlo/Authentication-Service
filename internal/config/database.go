package config

import (
	"fmt"
	"log/slog"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// ConnectPostgres opens the pool and verifies it is reachable before returning,
// so a misconfigured database surfaces at startup rather than on first request.
func ConnectPostgres(cfg *Config) (*gorm.DB, error) {
	level := gormlogger.Warn
	if !cfg.IsProduction() {
		level = gormlogger.Info
	}

	db, err := gorm.Open(postgres.Open(cfg.Database.DSN()), &gorm.Config{
		Logger: gormlogger.Default.LogMode(level),
		// The schema is owned by the migration files, not by GORM. Disabling
		// automatic constraint creation keeps GORM from drifting away from what
		// the migrations declare.
		DisableForeignKeyConstraintWhenMigrating: true,
		NowFunc:                                  func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		return nil, fmt.Errorf("config: open postgres: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("config: get sql.DB: %w", err)
	}

	sqlDB.SetMaxOpenConns(cfg.Database.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.Database.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.Database.ConnMaxLifetime)

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("config: ping postgres at %s:%s: %w", cfg.Database.Host, cfg.Database.Port, err)
	}

	slog.Info("postgres connected", "host", cfg.Database.Host, "database", cfg.Database.Name)
	return db, nil
}
