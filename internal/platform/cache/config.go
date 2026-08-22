package cache

import (
	"log/slog"
	"os"
	"strconv"
	"time"
)

// FromEnv builds a cache from the environment, falling back to Noop.
//
// REDIS_ADDR being unset is a normal, supported configuration: the service runs
// correctly without a cache, just slower. An unreachable Redis is likewise
// non-fatal — it logs a warning and degrades. Refusing to start because an
// optional accelerator is missing would turn a performance feature into an
// availability risk.
func FromEnv(service string) Cache {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		slog.Info("no REDIS_ADDR set; running without a cache", "service", service)
		return NewNoop()
	}

	c, err := NewRedis(RedisConfig{
		Addr:         addr,
		Password:     os.Getenv("REDIS_PASSWORD"),
		DB:           intOr("REDIS_DB", 0),
		Timeout:      durationOr("REDIS_TIMEOUT", 200*time.Millisecond),
		PoolSize:     intOr("REDIS_POOL_SIZE", 20),
		MinIdleConns: intOr("REDIS_MIN_IDLE_CONNS", 2),
		// ElastiCache requires TLS when encryption in transit is enabled, which
		// it should be in production.
		TLS: os.Getenv("REDIS_TLS") == "true",
	})
	if err != nil {
		slog.Warn("redis unavailable; running without a cache",
			"service", service, "addr", addr, "error", err)
		return NewNoop()
	}

	return c
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
