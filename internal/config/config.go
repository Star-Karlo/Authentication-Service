// Package config loads this service's configuration from the environment.
//
// The rule applied throughout: anything that is a security control has no
// default. A missing database password or signing key stops the process at
// startup instead of quietly falling back to something guessable, which is how
// the monolith ended up running with a JWT secret of "123".
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Environment string
	LogLevel    string

	// Cold storage (see internal/archive): audit rows older than
	// ArchiveAuditRetain move to S3 as Parquet; sessions dead for longer
	// than ArchiveSessionRetain are deleted. Needs ArchiveBucket.
	ArchiveBucket        string
	ArchiveRegion        string
	ArchivePrefix        string
	ArchiveAuditRetain   time.Duration
	ArchiveSessionRetain time.Duration
	ArchiveBatch         int
	ArchiveKeepAuditRows bool

	HTTPPort string
	GRPCPort string

	Database Database

	// AccessTokenTTL is how long an access token stays valid.
	//
	// It is a genuine trade rather than a tuning knob. Access tokens are
	// stateless — nothing is consulted to honour one — so a token cannot be
	// revoked before it expires, and the TTL IS the window in which a stolen
	// token works. Entitlement and permissions are embedded too, so it is also
	// how long a revoked module keeps working.
	//
	// Fifteen minutes, with refresh carrying the long life, is the safer shape
	// and remains the right default for production. Two hours was chosen for
	// development, where being signed out mid-task costs more than the
	// exposure. Set ACCESS_TOKEN_TTL explicitly per environment rather than
	// relying on this default.
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration

	// BcryptCost is configurable so it can be raised as hardware improves
	// without a code change.
	BcryptCost int

	// ServiceToken is the credential this service presents on outbound gRPC
	// calls, and AcceptedServiceTokens are the ones it honours inbound.
	ServiceToken          string
	AcceptedServiceTokens []string

	NotificationGRPCAddr string

	CORSAllowedOrigins []string

	// TrustedProxies is the CIDR list Gin trusts for X-Forwarded-For.
	// Empty keeps Gin's default of trusting every proxy, so an unset variable
	// changes nothing; set it to the VPC CIDR behind a load balancer.
	TrustedProxies []string

	// LoginRateLimit caps failed login attempts per identifier per window.
	LoginRateLimit  int
	LoginRateWindow time.Duration
}

type Database struct {
	Host            string
	Port            string
	User            string
	Password        string
	Name            string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// DSN renders the Postgres connection string.
func (d Database) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s TimeZone=Asia/Jakarta",
		d.Host, d.Port, d.User, d.Password, d.Name, d.SSLMode,
	)
}

// Load reads configuration, returning an error rather than exiting so that
// main can decide how to report it.
func Load() (*Config, error) {
	_ = godotenv.Load()

	env := envOr("ENVIRONMENT", "development")

	cfg := &Config{
		Environment: env,
		LogLevel:    envOr("LOG_LEVEL", "info"),
		HTTPPort:    envOr("HTTP_PORT", "5001"),
		GRPCPort:    envOr("GRPC_PORT", "6001"),

		Database: Database{
			Host:            envOr("DB_HOST", "localhost"),
			Port:            envOr("DB_PORT", "5432"),
			User:            envOr("DB_USER", "karlo"),
			Name:            envOr("DB_NAME", "karlo_auth"),
			SSLMode:         envOr("DB_SSLMODE", sslDefault(env)),
			MaxOpenConns:    intOr("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    intOr("DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: durationOr("DB_CONN_MAX_LIFETIME", time.Hour),
		},

		AccessTokenTTL:  durationOr("ACCESS_TOKEN_TTL", 2*time.Hour),
		RefreshTokenTTL: durationOr("REFRESH_TOKEN_TTL", 30*24*time.Hour),
		BcryptCost:      intOr("BCRYPT_COST", 12),

		NotificationGRPCAddr: envOr("NOTIFICATION_GRPC_ADDR", "localhost:6004"),

		CORSAllowedOrigins: splitOr("CORS_ALLOWED_ORIGINS", nil),
		TrustedProxies:     splitOr("TRUSTED_PROXIES", nil),

		LoginRateLimit:  intOr("LOGIN_RATE_LIMIT", 5),
		LoginRateWindow: durationOr("LOGIN_RATE_WINDOW", 15*time.Minute),

		ArchiveBucket:        envOr("ARCHIVE_BUCKET", ""),
		ArchiveRegion:        envOr("ARCHIVE_REGION", envOr("AWS_REGION", "ap-southeast-3")),
		ArchivePrefix:        envOr("ARCHIVE_PREFIX", "archive/auth"),
		ArchiveAuditRetain:   durationOr("ARCHIVE_RETAIN_AUDIT", 30*24*time.Hour),
		ArchiveSessionRetain: durationOr("ARCHIVE_RETAIN_SESSIONS", 30*24*time.Hour),
		ArchiveBatch:         intOr("ARCHIVE_BATCH", 100000),
		ArchiveKeepAuditRows: os.Getenv("ARCHIVE_KEEP_AUDIT_ROWS") == "true",
	}

	var missing []string

	cfg.Database.Password = os.Getenv("DB_PASSWORD")
	if cfg.Database.Password == "" {
		missing = append(missing, "DB_PASSWORD")
	}

	cfg.ServiceToken = os.Getenv("SERVICE_TOKEN")
	if cfg.ServiceToken == "" {
		missing = append(missing, "SERVICE_TOKEN")
	}

	cfg.AcceptedServiceTokens = splitOr("ACCEPTED_SERVICE_TOKENS", nil)
	if len(cfg.AcceptedServiceTokens) == 0 {
		missing = append(missing, "ACCEPTED_SERVICE_TOKENS")
	}

	// A wildcard CORS policy on an authenticated API lets any origin drive the
	// browser's credentials. Require the list to be stated.
	if len(cfg.CORSAllowedOrigins) == 0 {
		missing = append(missing, "CORS_ALLOWED_ORIGINS")
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("config: required environment variables not set: %s", strings.Join(missing, ", "))
	}

	if cfg.BcryptCost < 10 {
		return nil, fmt.Errorf("config: BCRYPT_COST must be at least 10, got %d", cfg.BcryptCost)
	}

	return cfg, nil
}

// IsProduction reports whether production safety rules apply.
//
// Terraform validates its environment variable as dev/staging/prod and passes
// it through unchanged, so the container sees ENVIRONMENT=prod. Matching only
// "production" left every production task with Swagger served, gRPC
// reflection on and every SQL statement logged. Both spellings are production.
func (c *Config) IsProduction() bool { return isProductionEnv(c.Environment) }

func isProductionEnv(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "production", "prod":
		return true
	}
	return false
}

func sslDefault(env string) string {
	if isProductionEnv(env) {
		return "require"
	}
	return "disable"
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func intOr(key string, fallback int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func durationOr(key string, fallback time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func splitOr(key string, fallback []string) []string {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return fallback
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
