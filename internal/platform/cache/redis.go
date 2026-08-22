package cache

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisConfig configures the Redis-backed cache.
type RedisConfig struct {
	Addr     string
	Password string
	DB       int

	// Timeout bounds every operation. It is deliberately short: a cache that
	// takes 500ms to answer is slower than most of the queries it fronts, and
	// waiting on it makes the request worse rather than better.
	Timeout time.Duration

	PoolSize     int
	MinIdleConns int

	// TLS is required by ElastiCache when encryption in transit is enabled.
	TLS bool
}

// Redis is the production cache.
type Redis struct {
	client  *redis.Client
	timeout time.Duration
}

// NewRedis connects and verifies the connection.
//
// A failure is returned so the caller can decide: services treat it as
// non-fatal and fall back to NoopCache, because running without a cache is
// slower but correct, while refusing to start is an outage.
func NewRedis(cfg RedisConfig) (*Redis, error) {
	if cfg.Addr == "" {
		return nil, errors.New("cache: no Redis address configured")
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 200 * time.Millisecond
	}
	poolSize := cfg.PoolSize
	if poolSize <= 0 {
		poolSize = 20
	}

	opts := &redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		PoolSize:     poolSize,
		MinIdleConns: cfg.MinIdleConns,
		// One retry only. A cache read is supposed to be the fast path; retrying
		// it repeatedly turns a slow cache into a slow request, which is the
		// opposite of the point.
		MaxRetries: 1,
	}
	if cfg.TLS {
		opts.TLSConfig = defaultTLSConfig(cfg.Addr)
	}

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("cache: ping redis at %s: %w", cfg.Addr, err)
	}

	slog.Info("redis connected", "addr", cfg.Addr, "db", cfg.DB)
	return &Redis{client: client, timeout: timeout}, nil
}

func (r *Redis) Get(ctx context.Context, key string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	raw, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		// A miss is the overwhelmingly common case and is not worth logging.
		if !errors.Is(err, redis.Nil) {
			slog.Warn("cache read failed, treating as a miss", "key", key, "error", err)
		}
		return nil, false
	}
	return raw, true
}

func (r *Redis) Set(ctx context.Context, key string, value []byte, ttl time.Duration) {
	// Detached from the caller's context: the value is already computed, and
	// losing the write because the request finished first is pure waste.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.timeout)
	defer cancel()

	if err := r.client.Set(ctx, key, value, ttl).Err(); err != nil {
		slog.Warn("cache write failed", "key", key, "error", err)
	}
}

func (r *Redis) Delete(ctx context.Context, keys ...string) {
	if len(keys) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.timeout)
	defer cancel()

	if err := r.client.Del(ctx, keys...).Err(); err != nil {
		// This one matters more than a failed Set: a failed invalidation means
		// stale data is served until the TTL expires.
		slog.Error("cache invalidation failed; entries will remain stale until they expire",
			"keys", keys, "error", err)
	}
}

// DeleteByPrefix removes a family of keys.
//
// SCAN, not KEYS: KEYS blocks the whole server while it walks the keyspace,
// which on a shared cache is an outage. SCAN is incremental and cursor-based,
// so it costs more round trips and blocks nobody.
func (r *Redis) DeleteByPrefix(ctx context.Context, prefix string) {
	// A generous budget, since this walks the keyspace rather than doing one
	// lookup, but still bounded so an invalidation cannot hang a request.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	var (
		cursor  uint64
		deleted int
	)
	for {
		keys, next, err := r.client.Scan(ctx, cursor, prefix+"*", 200).Result()
		if err != nil {
			slog.Error("cache prefix invalidation failed", "prefix", prefix, "error", err)
			return
		}

		if len(keys) > 0 {
			if err := r.client.Del(ctx, keys...).Err(); err != nil {
				slog.Error("cache prefix delete failed", "prefix", prefix, "error", err)
				return
			}
			deleted += len(keys)
		}

		cursor = next
		if cursor == 0 {
			break
		}
	}

	if deleted > 0 {
		slog.Debug("cache prefix invalidated", "prefix", prefix, "keys", deleted)
	}
}

// Increment is the rate-limiting primitive, implementing a FIXED window.
//
// INCR and the expiry run in one transaction so a crash between them cannot
// leave a counter with no TTL, which would lock an identifier out permanently.
//
// ExpireNX, not Expire: the TTL is set only when the key has none, so the
// window runs from the first attempt and then resets. Setting it on every
// increment would make the window slide, and a sliding window on a login
// limiter is a denial of service against the legitimate user — an attacker
// hammering someone's email address would keep extending the lockout for as
// long as they cared to, and the victim could never get back in.
//
// Note that Redis expiry has one-second granularity. A window shorter than a
// second is silently rounded up, so callers should not use one.
func (r *Redis) Increment(ctx context.Context, key string, window time.Duration) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	pipe := r.client.TxPipeline()
	incr := pipe.Incr(ctx, key)
	pipe.ExpireNX(ctx, key, window)

	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("cache: increment %s: %w", key, err)
	}

	return incr.Val(), nil
}

// SetIfAbsent is the idempotency and lock primitive, backed by SET NX.
func (r *Redis) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	won, err := r.client.SetNX(ctx, key, value, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("cache: set-if-absent %s: %w", key, err)
	}
	return won, nil
}

func (r *Redis) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	if err := r.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("cache: ping: %w", err)
	}
	return nil
}

func (r *Redis) Close() error { return r.client.Close() }
