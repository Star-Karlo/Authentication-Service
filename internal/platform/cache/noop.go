package cache

import (
	"context"
	"time"
)

// Noop is the cache used when none is configured.
//
// It exists so that no call site needs a nil check and no service needs a
// second code path for "running without Redis". Everything misses, nothing is
// stored, and the system runs at the speed of its databases.
type Noop struct{}

func NewNoop() *Noop { return &Noop{} }

func (Noop) Get(context.Context, string) ([]byte, bool) { return nil, false }

func (Noop) Set(context.Context, string, []byte, time.Duration) {}

func (Noop) Delete(context.Context, ...string) {}

func (Noop) DeleteByPrefix(context.Context, string) {}

// Increment reports an error rather than a fabricated count.
//
// Returning 1 would tell a rate limiter that every request is the first one,
// silently disabling it. The caller must decide whether to fail open or closed,
// and it cannot decide if it is not told.
func (Noop) Increment(context.Context, string, time.Duration) (int64, error) {
	return 0, ErrNoCache
}

// SetIfAbsent reports an error for the same reason: claiming the caller won the
// race would make every duplicate look like a first attempt.
func (Noop) SetIfAbsent(context.Context, string, []byte, time.Duration) (bool, error) {
	return false, ErrNoCache
}

func (Noop) Publish(context.Context, string, []byte) {}

func (Noop) Ping(context.Context) error { return nil }

func (Noop) Close() error { return nil }
