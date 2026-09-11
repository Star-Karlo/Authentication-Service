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
	"strings"
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

	// This suite TRUNCATEs users and companies. Pointed at the development
	// database it destroys the seed data, and the damage is invisible until
	// someone tries to sign in — which is exactly how it was found. The
	// database must be one created for testing, so its name has to say so.
	//
	// Naming is a weak check, but it is the only signal available here: the
	// test database and the development one are the same server, the same user
	// and the same schema, and nothing else distinguishes them.
	if !strings.Contains(dsn, "_test") {
		t.Fatalf("AUTH_TEST_DSN must name a database containing \"_test\": this suite "+
			"truncates users and companies, and %q looks like a database somebody "+
			"is using. Create one with:\n"+
			"  createdb karlo_auth_test && migrate -path migrations -database ... up",
			redactDSN(dsn))
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

// redactDSN strips the password before a DSN reaches a test log.
func redactDSN(dsn string) string {
	if at := strings.LastIndex(dsn, "@"); at != -1 {
		if scheme := strings.Index(dsn, "://"); scheme != -1 && scheme+3 < at {
			return dsn[:scheme+3] + "***" + dsn[at:]
		}
	}
	return dsn
}

func resetTables(t *testing.T, db *gorm.DB) {
	t.Helper()

	err := db.Exec(`
		TRUNCATE TABLE
			auth_audit_log, user_documents,
			api_keys, device_tokens, sessions, user_product_access,
			users, roles, companies
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
		Language:     "id",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("could not seed a user: %v", err)
	}
	return user
}

func ctx() context.Context { return context.Background() }

func strptr(s string) *string { return &s }
