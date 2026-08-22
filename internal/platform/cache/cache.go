// Package cache is the shared caching layer.
//
// One principle runs through everything here: **a cache failure is never a
// request failure.** Redis being slow, full or absent degrades the system to
// the speed of its source of truth, and nothing more. Every read returns a miss
// on error, every write logs and continues, and no method returns an error the
// caller is expected to handle. Code that treats a cache as a dependency it can
// fail on has traded a fast system for a fragile one.
//
// The second principle is that **nothing authoritative is cached**. Order
// status, invoice totals, session validity and permission grants are read from
// their owner every time. What is cached is data that is expensive to fetch,
// read far more often than written, and harmless to serve a few seconds stale.
package cache

import (
	"context"
	"encoding/json"
	"time"
)

// Cache is the interface services depend on.
//
// Note the signatures: Get reports a miss rather than an error, and Set returns
// nothing at all. That is deliberate — it makes the degradation policy
// impossible to get wrong at a call site.
type Cache interface {
	// Get returns the stored bytes, or false on a miss, an expiry, or any
	// backend failure.
	Get(ctx context.Context, key string) ([]byte, bool)

	// Set stores a value. A failure is logged, not returned.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration)

	// Delete removes keys. Used for explicit invalidation after a write.
	Delete(ctx context.Context, keys ...string)

	// DeleteByPrefix removes every key under a prefix. Used when one write
	// invalidates a family of entries, such as an edit to a catalogue
	// invalidating all of its cached pages.
	DeleteByPrefix(ctx context.Context, prefix string)

	// Increment adds one to a counter and returns the new value, setting the
	// TTL on first use. This is the rate-limiting primitive; it returns an
	// error because a limiter that silently fails open is a limiter that does
	// not limit, and the caller must decide what to do about it.
	Increment(ctx context.Context, key string, window time.Duration) (int64, error)

	// SetIfAbsent stores a value only when the key is unset, reporting whether
	// it won. This is the idempotency and distributed-lock primitive; like
	// Increment it returns an error, because "I could not tell whether this was
	// a duplicate" is a decision the caller must make.
	SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)

	// Ping reports whether the backend is reachable, for health endpoints.
	Ping(ctx context.Context) error

	// Close releases the connection.
	Close() error
}

// GetJSON reads and decodes a cached value.
//
// A decode failure is treated as a miss: a stale entry written by an older
// version of the struct must not fail the request, it must simply be refetched.
func GetJSON[T any](ctx context.Context, c Cache, key string, out *T) bool {
	raw, ok := c.Get(ctx, key)
	if !ok {
		return false
	}
	if err := json.Unmarshal(raw, out); err != nil {
		// The entry is unusable; drop it so the next caller does not repeat the
		// same failed decode.
		c.Delete(ctx, key)
		return false
	}
	return true
}

// SetJSON encodes and stores a value. An encoding failure is silently skipped:
// failing to cache is not a reason to fail the operation that produced the data.
func SetJSON(ctx context.Context, c Cache, key string, value any, ttl time.Duration) {
	raw, err := json.Marshal(value)
	if err != nil {
		return
	}
	c.Set(ctx, key, raw, ttl)
}
