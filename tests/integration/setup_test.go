//go:build integration

// Package integration exercises the authentication repositories against a real
// Postgres.
//
// The behaviours covered here depend on the database rather than on Go: partial
// unique indexes, soft-delete interaction with those indexes, and cascading
// revocation. A unit test cannot say whether the index in the migration
// actually behaves as intended.
//
//	go test -tags=integration ./tests/integration/... -v
package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()

	dsn := os.Getenv("AUTH_TEST_DSN")
	if dsn == "" {
		t.Skip("AUTH_TEST_DSN is not set; skipping integration tests")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger:  logger.Default.LogMode(logger.Silent),
		NowFunc: func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		t.Fatalf("could not connect to %s: %v", dsn, err)
	}

	// Bound the pool as the service does, so a concurrency test cannot exhaust
	// the server's connection limit and look like a product failure.
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("could not reach the underlying pool: %v", err)
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)

	return db
}

func resetTables(t *testing.T, db *gorm.DB) {
	t.Helper()

	err := db.Exec(`
		TRUNCATE TABLE
			auth_audit_log, collaboration_invites, user_documents,
			api_keys, device_tokens, sessions, users, companies
		RESTART IDENTITY CASCADE
	`).Error
	if err != nil {
		t.Fatalf("could not reset tables: %v", err)
	}
}

// seedCompany inserts a tenant.
func seedCompany(t *testing.T, db *gorm.DB) *models.Company {
	t.Helper()

	company := &models.Company{
		Name:     "Test Co " + uuid.NewString()[:8],
		Role:     "shipper",
		Settings: models.CompanySettings{PPNPercentage: 0.02, PPH23Percentage: 0.11},
	}
	if err := db.Create(company).Error; err != nil {
		t.Fatalf("could not seed a company: %v", err)
	}
	return company
}

// seedUser inserts an account with the given email.
func seedUser(t *testing.T, db *gorm.DB, companyID uuid.UUID, email string) *models.User {
	t.Helper()

	user := &models.User{
		CompanyID:    &companyID,
		Email:        &email,
		PasswordHash: "$2a$12$notarealhashbutlongenoughtolooklikeone000000000000000",
		Role:         "shipper",
		AccountType:  "mainAccount",
		Permission:   models.Permission{},
		Language:     "id",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("could not seed a user: %v", err)
	}
	return user
}

func ctx() context.Context { return context.Background() }

func strptr(s string) *string { return &s }
