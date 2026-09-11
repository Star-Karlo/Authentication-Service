package revocation

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Channel carries live announcements.
const Channel = "karlo:revocations"

// keyPrefix namespaces the durable copy of the list.
const keyPrefix = "revoked:"

// Store publishes and reads revocations through Redis.
//
// Two mechanisms, deliberately, because neither is sufficient alone:
//
//   - PUB/SUB delivers immediately, and only to whoever is listening at that
//     instant. A service restarting, or briefly disconnected, misses the
//     message permanently and silently.
//   - KEYS with a TTL are durable and can be read in full at any time, but tell
//     nobody when they change.
//
// Together they give immediacy from the first and correctness from the second:
// announcements arrive at once, and a full resync repairs anything missed.
type Store struct {
	client *redis.Client

	// maxTokenLife is how long an entry must survive. Beyond it the token would
	// be refused on its own expiry, so the entry stops doing anything.
	maxTokenLife time.Duration
}

func NewStore(client *redis.Client, maxTokenLife time.Duration) *Store {
	if maxTokenLife <= 0 {
		maxTokenLife = 2 * time.Hour
	}
	return &Store{client: client, maxTokenLife: maxTokenLife}
}

func key(e Event) string { return keyPrefix + string(e.Kind) + ":" + e.ID }

// Publish records a revocation and announces it.
//
// The durable write happens FIRST. If the order were reversed, a subscriber
// could act on an announcement, restart, resync, and find no record of it —
// briefly un-revoking something that had already been revoked.
func (s *Store) Publish(ctx context.Context, e Event) error {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}

	payload, err := Encode(e)
	if err != nil {
		return err
	}

	if err := s.client.Set(ctx, key(e), payload, s.maxTokenLife).Err(); err != nil {
		return fmt.Errorf("revocation: record: %w", err)
	}
	if err := s.client.Publish(ctx, Channel, payload).Err(); err != nil {
		// The durable write succeeded, so the revocation is not lost — every
		// subscriber picks it up on its next resync. Worth logging as a delay
		// rather than a failure.
		slog.WarnContext(ctx, "revocation recorded but not announced; it will "+
			"take effect at the next resync rather than immediately",
			"kind", e.Kind, "id", e.ID, "error", err)
	}
	return nil
}

// All reads the complete list, for the periodic resync.
func (s *Store) All(ctx context.Context) ([]Event, error) {
	var (
		events []Event
		cursor uint64
	)
	for {
		keys, next, err := s.client.Scan(ctx, cursor, keyPrefix+"*", 512).Result()
		if err != nil {
			return nil, fmt.Errorf("revocation: scan: %w", err)
		}
		for _, k := range keys {
			raw, err := s.client.Get(ctx, k).Bytes()
			if err != nil {
				// Expired between the scan and the read, which is ordinary.
				continue
			}
			e, derr := Decode(raw)
			if derr != nil {
				slog.WarnContext(ctx, "ignoring an unreadable revocation entry",
					"key", k, "error", derr)
				continue
			}
			events = append(events, e)
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	return events, nil
}

// Watch keeps a list in step with the store until the context ends.
//
// It runs the resync FIRST, so a service is correct from the moment it starts
// rather than from the first announcement it happens to catch.
func (s *Store) Watch(ctx context.Context, list *List, resyncEvery time.Duration) {
	if resyncEvery <= 0 {
		resyncEvery = 30 * time.Second
	}

	s.resync(ctx, list)

	sub := s.client.Subscribe(ctx, Channel)
	defer func() { _ = sub.Close() }()
	messages := sub.Channel()

	ticker := time.NewTicker(resyncEvery)
	defer ticker.Stop()

	prune := time.NewTicker(s.maxTokenLife / 2)
	defer prune.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case msg, ok := <-messages:
			if !ok {
				// The subscription dropped. A resync covers whatever was missed
				// while it was gone.
				list.MarkDegraded(fmt.Errorf("revocation: subscription closed"))
				s.resync(ctx, list)
				sub = s.client.Subscribe(ctx, Channel)
				messages = sub.Channel()
				continue
			}
			e, err := Decode([]byte(msg.Payload))
			if err != nil {
				slog.WarnContext(ctx, "ignoring an unreadable revocation announcement",
					"error", err)
				continue
			}
			list.Apply(e)
			slog.InfoContext(ctx, "revocation applied",
				"kind", e.Kind, "id", redactID(e.ID))

		case <-ticker.C:
			s.resync(ctx, list)

		case <-prune.C:
			list.Prune(s.maxTokenLife)
		}
	}
}

func (s *Store) resync(ctx context.Context, list *List) {
	events, err := s.All(ctx)
	if err != nil {
		list.MarkDegraded(err)
		return
	}
	list.Replace(events)
}

// redactID trims an identifier for a log line. The full value belongs in the
// database, not in a log that a wider audience can read.
func redactID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "…"
}

var _ = strings.TrimSpace

// FromEnv builds a store and a list from REDIS_ADDR, and starts watching.
//
// Returns a NoopChecker when no Redis is configured. That keeps a deployment
// without Redis running, with the same consequence as a degraded list: a
// revocation takes effect when the token expires rather than at once. It is
// announced at startup so nobody discovers it during an incident.
func FromEnv(ctx context.Context, service string, maxTokenLife time.Duration) (Checker, *Store) {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		slog.Warn("no REDIS_ADDR set: revocations cannot be announced, so a "+
			"suspension or permission change will not take effect until the "+
			"affected tokens expire",
			"service", service, "token_lifetime", maxTokenLife)
		return NoopChecker{}, nil
	}

	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: os.Getenv("REDIS_PASSWORD"),
	})

	store := NewStore(client, maxTokenLife)
	list := NewList()

	go store.Watch(ctx, list, 30*time.Second)

	slog.Info("watching for revocations", "service", service, "addr", addr)
	return list, store
}
