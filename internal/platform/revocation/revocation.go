// Package revocation makes an access token stop working before it expires.
//
// An access token is verified locally: a service checks the signature and
// trusts what is inside, with no round trip. That is what makes it cheap, and
// it is also the problem — nothing can be taken away until the token expires.
// With a two-hour lifetime that means suspending somebody leaves them working
// for two hours, and narrowing a role does nothing for two hours.
//
// The usual fix is to ask the authentication service on every request. That
// works and it is expensive: every service, every request, a network hop, and
// authentication on the critical path of the whole system.
//
// This does the opposite. Authentication ANNOUNCES a change; every service
// keeps a small local list and answers from memory. The common case — a token
// that is perfectly valid — costs a map lookup. Only the announcement travels.
//
// The list is deliberately tiny. Entries expire when the longest possible token
// would have expired anyway, because after that the token is refused on its own.
package revocation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Kind is what a revocation applies to.
type Kind string

const (
	// KindSession ends ONE session, named by its token id. Used for logout and
	// for evicting the older login of a single-device account.
	KindSession Kind = "session"

	// KindUser ends every session a person holds. Used for suspension, a
	// password change, a role change, and a change to their own permissions —
	// anything where what they may do is no longer what their token says.
	KindUser Kind = "user"

	// KindCompany ends every session at a company. Used when entitlement
	// changes: a module withdrawn must stop working for everyone at once, not
	// person by person as each token happens to expire.
	KindCompany Kind = "company"
)

// Event is one announcement.
type Event struct {
	Kind Kind   `json:"kind"`
	ID   string `json:"id"`

	// At is the moment from which tokens are no longer accepted.
	//
	// For a user or a company this is a CUTOFF rather than a list: any token
	// issued before it is refused. That is what keeps the list small — ending
	// a thousand sessions is one entry, not a thousand — and it is also what
	// makes it correct when a session was created after the change and should
	// therefore still work.
	At time.Time `json:"at"`
}

// Checker answers whether a token has been revoked.
type Checker interface {
	// Revoked reports whether a token should be refused, given its session id,
	// the user and company it names, and when it was issued.
	Revoked(sessionID, userID, companyID string, issuedAt time.Time) bool
}

// List is the in-memory copy every service keeps.
//
// Reads are far more common than writes — one per request against one per
// administrative action — so it is a plain map behind an RWMutex rather than
// anything cleverer.
type List struct {
	mu sync.RWMutex

	// sessions holds ended sessions and when their entry may be forgotten.
	sessions map[string]time.Time

	// users and companies hold CUTOFFS: a token issued before the stored time
	// is refused.
	users     map[string]time.Time
	companies map[string]time.Time

	// degraded records that the backing store could not be reached, so the
	// answer below is a guess rather than a fact.
	degraded bool
}

func NewList() *List {
	return &List{
		sessions:  map[string]time.Time{},
		users:     map[string]time.Time{},
		companies: map[string]time.Time{},
	}
}

// Revoked reports whether a token should be refused.
func (l *List) Revoked(sessionID, userID, companyID string, issuedAt time.Time) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if sessionID != "" {
		if _, ended := l.sessions[sessionID]; ended {
			return true
		}
	}
	// A cutoff refuses anything issued before it. Tokens minted afterwards —
	// a fresh login by the same person — are unaffected, which is what makes
	// "sign in again" a working remedy.
	if userID != "" {
		if cutoff, ok := l.users[userID]; ok && issuedAt.Before(cutoff) {
			return true
		}
	}
	if companyID != "" {
		if cutoff, ok := l.companies[companyID]; ok && issuedAt.Before(cutoff) {
			return true
		}
	}
	return false
}

// Apply records an announcement.
func (l *List) Apply(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	switch e.Kind {
	case KindSession:
		l.sessions[e.ID] = e.At
	case KindUser:
		// Keep the LATER cutoff. Two revocations for one person must not let
		// the earlier one narrow the later.
		if cur, ok := l.users[e.ID]; !ok || e.At.After(cur) {
			l.users[e.ID] = e.At
		}
	case KindCompany:
		if cur, ok := l.companies[e.ID]; !ok || e.At.After(cur) {
			l.companies[e.ID] = e.At
		}
	}
}

// Replace swaps the whole list, used by the periodic resync.
func (l *List) Replace(events []Event) {
	fresh := NewList()
	for _, e := range events {
		fresh.Apply(e)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.sessions, l.users, l.companies = fresh.sessions, fresh.users, fresh.companies
	l.degraded = false
}

// Prune drops entries older than the longest token lifetime, since a token
// that old is refused on its own expiry and the entry no longer does anything.
func (l *List) Prune(maxTokenLife time.Duration) {
	cutoff := time.Now().Add(-maxTokenLife)

	l.mu.Lock()
	defer l.mu.Unlock()
	for id, at := range l.sessions {
		if at.Before(cutoff) {
			delete(l.sessions, id)
		}
	}
	for id, at := range l.users {
		if at.Before(cutoff) {
			delete(l.users, id)
		}
	}
	for id, at := range l.companies {
		if at.Before(cutoff) {
			delete(l.companies, id)
		}
	}
}

// MarkDegraded records that the backing store is unreachable.
//
// The list then answers from whatever it last knew, which is FAIL-OPEN: a
// revocation announced during the outage is missed until the store returns.
//
// The alternative — refusing every token while the store is unreachable — turns
// a cache outage into a total outage of every service, and does so for a window
// that is at most one token lifetime of extra exposure. Failing open is the
// right trade here, but it is a trade, so it is announced loudly rather than
// absorbed.
func (l *List) MarkDegraded(reason error) {
	l.mu.Lock()
	wasDegraded := l.degraded
	l.degraded = true
	l.mu.Unlock()

	if !wasDegraded {
		slog.Error("revocation list is stale: the store is unreachable, so "+
			"suspensions and permission changes will NOT take effect until it "+
			"returns; tokens already issued keep working until they expire",
			"error", reason)
	}
}

// Degraded reports whether the list is answering from stale knowledge.
func (l *List) Degraded() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.degraded
}

// Size reports how many entries are held, for a health endpoint.
func (l *List) Size() (sessions, users, companies int) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.sessions), len(l.users), len(l.companies)
}

// Encode renders an event for transport.
func Encode(e Event) ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("revocation: encode: %w", err)
	}
	return b, nil
}

// Decode parses an event.
func Decode(b []byte) (Event, error) {
	var e Event
	if err := json.Unmarshal(b, &e); err != nil {
		return Event{}, fmt.Errorf("revocation: decode: %w", err)
	}
	if e.Kind == "" || e.ID == "" {
		return Event{}, fmt.Errorf("revocation: incomplete event %q", string(b))
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	return e, nil
}

// NoopChecker never revokes. Used where no store is configured, so a service
// runs without one — with the same consequence as a degraded list, and the
// same reason for accepting it.
type NoopChecker struct{}

func (NoopChecker) Revoked(string, string, string, time.Time) bool { return false }

var _ Checker = (*List)(nil)
var _ Checker = NoopChecker{}

// ContextKey is unused but kept so callers cannot accidentally collide with a
// string key in the request context.
type contextKey struct{}

var _ = context.Background
