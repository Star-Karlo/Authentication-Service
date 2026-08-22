//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/karlo/authentication-service/internal/platform/cache"
)

// newCache connects to a real Redis, skipping when none is configured.
func newCache(t *testing.T) cache.Cache {
	t.Helper()

	addr := os.Getenv("REDIS_TEST_ADDR")
	if addr == "" {
		t.Skip("REDIS_TEST_ADDR is not set; skipping cache integration tests")
	}

	c, err := cache.NewRedis(cache.RedisConfig{Addr: addr, Timeout: time.Second})
	if err != nil {
		t.Fatalf("could not connect to redis at %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestCacheReadWriteRoundTrip(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()

	key := cache.Key("test", "roundtrip", t.Name())
	c.Delete(ctx, key)

	if _, ok := c.Get(ctx, key); ok {
		t.Fatal("a key that was just deleted reported a hit")
	}

	c.Set(ctx, key, []byte("value"), time.Minute)

	got, ok := c.Get(ctx, key)
	if !ok {
		t.Fatal("a key that was just written reported a miss")
	}
	if string(got) != "value" {
		t.Errorf("got %q, want %q", got, "value")
	}

	c.Delete(ctx, key)
	if _, ok := c.Get(ctx, key); ok {
		t.Error("the key survived deletion")
	}
}

func TestCacheEntriesExpire(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()

	key := cache.Key("test", "expiry", t.Name())
	c.Set(ctx, key, []byte("temporary"), 300*time.Millisecond)

	if _, ok := c.Get(ctx, key); !ok {
		t.Fatal("the entry was not readable immediately after writing")
	}

	time.Sleep(600 * time.Millisecond)

	if _, ok := c.Get(ctx, key); ok {
		t.Error("the entry outlived its TTL")
	}
}

// TestPrefixInvalidationRemovesTheFamilyAndNothingElse covers the invalidation
// a catalogue edit performs. Deleting too little serves stale data; deleting too
// much stampedes the database.
func TestPrefixInvalidationScopesCorrectly(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()

	family := cache.Prefix("test", "invalidation", "truckType")
	// A sibling whose name starts with the same characters. Without the
	// trailing colon in Prefix, deleting "truck" would take "truckGroup" too.
	sibling := cache.Key("test", "invalidation", "truckTypeExtra", "page", "0")

	for _, page := range []string{"0", "1", "2"} {
		c.Set(ctx, cache.Key("test", "invalidation", "truckType", "page", page), []byte("x"), time.Minute)
	}
	c.Set(ctx, sibling, []byte("x"), time.Minute)

	c.DeleteByPrefix(ctx, family)

	for _, page := range []string{"0", "1", "2"} {
		if _, ok := c.Get(ctx, cache.Key("test", "invalidation", "truckType", "page", page)); ok {
			t.Errorf("page %s survived invalidation", page)
		}
	}
	if _, ok := c.Get(ctx, sibling); !ok {
		t.Error("invalidation reached a sibling key whose name shares a prefix")
	}

	c.Delete(ctx, sibling)
}

// TestIncrementIsAtomicUnderConcurrency is the rate limiter's core guarantee.
// If concurrent increments lost updates, an attacker could exceed the limit
// simply by sending requests in parallel — which is how they would send them.
func TestIncrementIsAtomicUnderConcurrency(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()

	key := cache.Key("test", "ratelimit", t.Name())
	c.Delete(ctx, key)

	const callers = 100

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		seen  = map[int64]bool{}
		errs  []error
		start = make(chan struct{})
	)

	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			n, err := c.Increment(ctx, key, time.Minute)

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			if seen[n] {
				errs = append(errs, errors.New("a counter value was handed out twice"))
			}
			seen[n] = true
		}()
	}

	close(start)
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("%d failures, first: %v", len(errs), errs[0])
	}
	if len(seen) != callers {
		t.Errorf("got %d distinct values from %d increments; updates were lost", len(seen), callers)
	}
	for i := int64(1); i <= callers; i++ {
		if !seen[i] {
			t.Errorf("value %d was never produced", i)
		}
	}

	c.Delete(ctx, key)
}

// TestIncrementSetsAnExpiry guards against the counter that never resets. A key
// with no TTL locks an identifier out permanently.
func TestIncrementSetsAnExpiry(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()

	key := cache.Key("test", "ratelimit", "expiry", t.Name())
	c.Delete(ctx, key)

	// One second is Redis's finest expiry granularity; anything shorter is
	// silently rounded up, which is what made an earlier version of this test
	// fail for the wrong reason.
	const window = time.Second

	if _, err := c.Increment(ctx, key, window); err != nil {
		t.Fatalf("increment failed: %v", err)
	}
	// The second increment must NOT extend the window. If it did, a persistent
	// attacker could keep a victim locked out indefinitely.
	if _, err := c.Increment(ctx, key, window); err != nil {
		t.Fatalf("increment failed: %v", err)
	}

	time.Sleep(1500 * time.Millisecond)

	n, err := c.Increment(ctx, key, window)
	if err != nil {
		t.Fatalf("increment failed: %v", err)
	}
	if n != 1 {
		t.Errorf("the counter did not reset after its window; got %d", n)
	}

	c.Delete(ctx, key)
}

// TestSetIfAbsentHasExactlyOneWinner is the idempotency guarantee. Two retries
// arriving together must not both conclude they are the original.
func TestSetIfAbsentHasExactlyOneWinner(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()

	key := cache.Key("test", "idempotency", t.Name())
	c.Delete(ctx, key)

	const callers = 50

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		wins  int
		errs  []error
		start = make(chan struct{})
	)

	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			won, err := c.SetIfAbsent(ctx, key, []byte("claimed"), time.Minute)

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			if won {
				wins++
			}
		}()
	}

	close(start)
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("%d failures, first: %v", len(errs), errs[0])
	}
	if wins != 1 {
		t.Errorf("%d callers claimed the key; exactly 1 should have", wins)
	}

	c.Delete(ctx, key)
}

// TestJSONHelpersRoundTrip covers the typed accessors services actually use.
func TestJSONHelpersRoundTrip(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()

	type payload struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	key := cache.Key("test", "json", t.Name())
	c.Delete(ctx, key)

	want := payload{Name: "truck type", Count: 7}
	cache.SetJSON(ctx, c, key, want, time.Minute)

	var got payload
	if !cache.GetJSON(ctx, c, key, &got) {
		t.Fatal("the value could not be read back")
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}

	// An entry that no longer decodes into the current struct must be treated
	// as a miss and dropped, not surfaced as an error. A shape change during a
	// deploy would otherwise fail every request until the TTL passed.
	c.Set(ctx, key, []byte("{not json"), time.Minute)
	var broken payload
	if cache.GetJSON(ctx, c, key, &broken) {
		t.Error("an undecodable entry reported a hit")
	}
	if _, ok := c.Get(ctx, key); ok {
		t.Error("an undecodable entry was left in place for the next caller")
	}
}

// TestNoopCacheDegradesSafely covers the path taken when no Redis is
// configured, which must be a supported mode rather than a broken one.
func TestNoopCacheDegradesSafely(t *testing.T) {
	c := cache.NewNoop()
	ctx := context.Background()

	c.Set(ctx, "k", []byte("v"), time.Minute)
	if _, ok := c.Get(ctx, "k"); ok {
		t.Error("the noop cache returned a hit")
	}
	c.Delete(ctx, "k")
	c.DeleteByPrefix(ctx, "k")

	// The two primitives that cannot be faked must say so rather than lie.
	if _, err := c.Increment(ctx, "k", time.Minute); !errors.Is(err, cache.ErrNoCache) {
		t.Errorf("Increment err = %v, want ErrNoCache", err)
	}
	if _, err := c.SetIfAbsent(ctx, "k", []byte("v"), time.Minute); !errors.Is(err, cache.ErrNoCache) {
		t.Errorf("SetIfAbsent err = %v, want ErrNoCache", err)
	}
}
