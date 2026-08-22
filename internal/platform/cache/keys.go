package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Namespace is the prefix on every key this platform writes.
//
// It exists so that a Redis shared with anything else stays legible, and so
// that `SCAN karlo:*` finds everything the platform owns and nothing it does
// not.
const Namespace = "karlo"

// SchemaVersion is embedded in every key.
//
// Bump it when the *shape* of a cached value changes. That instantly orphans
// every entry of the old shape without a flush and without a deploy-ordering
// problem: old instances read v1 keys, new instances read v2 keys, and the old
// ones expire on their own. Flushing instead would stampede the databases at
// the worst possible moment, during a deploy.
const SchemaVersion = "v1"

// Key builds a namespaced key from its parts.
//
//	Key("masterdata", "catalog", "truckType", "page", "0")
//	  -> "karlo:v1:masterdata:catalog:truckType:page:0"
//
// Parts are joined with colons, which is the Redis convention and what every
// Redis inspection tool expects when grouping keys.
func Key(parts ...string) string {
	cleaned := make([]string, 0, len(parts)+2)
	cleaned = append(cleaned, Namespace, SchemaVersion)
	for _, p := range parts {
		// A colon inside a part would create a level that does not exist and
		// break prefix deletion, so replace it.
		cleaned = append(cleaned, strings.ReplaceAll(p, ":", "_"))
	}
	return strings.Join(cleaned, ":")
}

// Prefix builds the key prefix for a family of entries, for DeleteByPrefix.
//
//	Prefix("masterdata", "catalog", "truckType")
//	  -> "karlo:v1:masterdata:catalog:truckType:"
//
// The trailing colon matters: without it, deleting the prefix for "truck" would
// also delete "truckGroup".
func Prefix(parts ...string) string {
	return Key(parts...) + ":"
}

// Fingerprint reduces a long or variable input to a short stable token.
//
// Listing keys embed the caller's filters and sorts, which can be arbitrarily
// long and contain any characters. Hashing keeps keys bounded and safe while
// remaining deterministic, so the same query maps to the same entry.
func Fingerprint(input string) string {
	sum := sha256.Sum256([]byte(input))
	// 8 bytes is ample: these discriminate between query shapes within one
	// tenant and entity, not across a global namespace.
	return hex.EncodeToString(sum[:8])
}
