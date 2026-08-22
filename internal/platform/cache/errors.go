package cache

import "errors"

// ErrNoCache is returned by the primitives that cannot be faked when no cache
// is configured: rate limiting and idempotency.
//
// Callers must handle it explicitly, and the right handling differs. A login
// rate limiter should fail open — refusing every login because Redis is down is
// a self-inflicted outage, and the audit log still records the attempts. An
// idempotency check should proceed and accept the small risk of a duplicate
// notification, because dropping a notification is worse than sending it twice.
var ErrNoCache = errors.New("cache: no cache configured")
