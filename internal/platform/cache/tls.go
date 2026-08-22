package cache

import (
	"crypto/tls"
	"strings"
)

// defaultTLSConfig builds the TLS settings ElastiCache expects when encryption
// in transit is enabled.
//
// The server name is derived from the address so certificate verification
// actually happens. Disabling verification here would leave the connection
// encrypted but unauthenticated, which protects against a passive listener and
// not against anything else.
func defaultTLSConfig(addr string) *tls.Config {
	host := addr
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		host = addr[:idx]
	}
	return &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
}
