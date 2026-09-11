//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/karlo/authentication-service/internal/platform/revocation"
)

// TestAnnouncementReachesAnotherService is the whole point of the mechanism,
// end to end against a real Redis.
//
// One process publishes; a second, which knows nothing about the first, must
// refuse the token. Unit tests cover the list's logic; only this covers whether
// the announcement actually crosses a process boundary — which is the part that
// silently does not work if pub/sub, the durable write, or the resync is wrong.
func TestAnnouncementReachesAnotherService(t *testing.T) {
	client := testRedis(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	publisher := revocation.NewStore(client, time.Hour)

	// The "other service": its own list, watching independently.
	subscriber := revocation.NewList()
	go publisher.Watch(ctx, subscriber, time.Second)
	time.Sleep(300 * time.Millisecond) // let the initial resync and subscribe settle

	issued := time.Now().Add(-time.Minute)
	if subscriber.Revoked("", "user-live", "", issued) {
		t.Fatal("nothing has been revoked yet")
	}

	err := publisher.Publish(ctx, revocation.Event{
		Kind: revocation.KindUser, ID: "user-live", At: time.Now(),
	})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	if !eventually(2*time.Second, func() bool {
		return subscriber.Revoked("", "user-live", "", issued)
	}) {
		t.Error("the announcement never reached the other service; a suspension " +
			"would take effect only when the token expired")
	}
}

// TestResyncRepairsAMissedAnnouncement covers the hole pub/sub leaves.
//
// A service that is restarting, or briefly disconnected, misses a live message
// permanently and silently. The periodic full read is what makes that
// survivable, so it is worth proving rather than assuming: here the revocation
// is published BEFORE the subscriber exists, which no amount of listening could
// have caught.
func TestResyncRepairsAMissedAnnouncement(t *testing.T) {
	client := testRedis(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := revocation.NewStore(client, time.Hour)

	err := store.Publish(ctx, revocation.Event{
		Kind: revocation.KindUser, ID: "user-missed", At: time.Now(),
	})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Only now does the service start. It never heard the announcement.
	late := revocation.NewList()
	go store.Watch(ctx, late, time.Second)

	if !eventually(3*time.Second, func() bool {
		return late.Revoked("", "user-missed", "", time.Now().Add(-time.Minute))
	}) {
		t.Error("a service starting after the announcement must still learn of it; " +
			"otherwise a restart quietly un-revokes everything announced while it was down")
	}
}

func testRedis(t *testing.T) *redis.Client {
	t.Helper()

	client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skipf("no Redis on localhost:6379; skipping: %v", err)
	}

	// Leave no revocations behind: they would refuse tokens in later tests.
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		keys, _ := client.Keys(c, "revoked:*").Result()
		if len(keys) > 0 {
			client.Del(c, keys...)
		}
		_ = client.Close()
	})
	return client
}

func eventually(within time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}
