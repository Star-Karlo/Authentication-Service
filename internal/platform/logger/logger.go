// Package logger provides the structured logger every service shares, so log
// lines from four processes can be correlated in one place.
//
// Output goes to stdout as JSON always, and additionally to Fluentd when one is
// configured. Stdout is never disabled: container platforms collect it, and a
// service whose only log sink is an unreachable Fluentd is a service with no
// logs at all. That is the failure mode the legacy `logger.Init(host, port)`
// had, since it swallowed connection errors and logged nothing.
package logger

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"
)

type ctxKey struct{}

// Config describes where logs go.
type Config struct {
	// Service names the emitting service, attached to every line so a shipped
	// log is attributable without inspecting the container.
	Service string
	// Level is one of debug, info, warn, error.
	Level string
	// Environment is attached to every line, so staging and production lines
	// are distinguishable in a shared index.
	Environment string
	// Fluentd, when non-nil, adds a second sink.
	Fluentd *FluentdConfig
}

// FluentdConfig describes the Fluentd forwarder.
type FluentdConfig struct {
	Host string
	Port int
	// TagPrefix namespaces this service's records, e.g. "karlo" yields tags
	// like "karlo.business".
	TagPrefix string
	// Async keeps log calls from blocking on a slow or absent collector.
	// It should be true everywhere except in tests.
	Async bool
	// BufferLimit caps how many records are held while the collector is
	// unreachable, bounding memory during an outage.
	BufferLimit int
	// Timeout bounds a single write.
	Timeout time.Duration
}

// Init configures the process-wide logger.
//
// It never returns an error. A Fluentd that cannot be reached degrades to
// stdout-only with a warning, because losing log shipping must not stop a
// service from starting.
func Init(cfg Config) {
	handlers := []slog.Handler{
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLevel(cfg.Level)}),
	}

	if cfg.Fluentd != nil {
		fh, err := newFluentdHandler(*cfg.Fluentd, cfg.Service, parseLevel(cfg.Level))
		if err != nil {
			// Deliberately not fatal.
			slog.New(handlers[0]).Warn("fluentd unavailable, logging to stdout only",
				"host", cfg.Fluentd.Host, "port", cfg.Fluentd.Port, "error", err)
		} else {
			handlers = append(handlers, fh)
			registerCloser(fh)
		}
	}

	attrs := []slog.Attr{slog.String("service", cfg.Service)}
	if cfg.Environment != "" {
		attrs = append(attrs, slog.String("env", cfg.Environment))
	}

	handler := handlers[0]
	if len(handlers) > 1 {
		handler = &fanoutHandler{handlers: handlers}
	}

	slog.SetDefault(slog.New(handler.WithAttrs(attrs)))
}

// InitFromEnv configures logging from the environment, which is how every
// service's main does it.
//
// FLUENTD_HOST enables shipping; when it is unset, logging is stdout-only. That
// is the right default for local development and for platforms that collect
// stdout themselves.
func InitFromEnv(service string) {
	cfg := Config{
		Service:     service,
		Level:       envOr("LOG_LEVEL", "info"),
		Environment: envOr("ENVIRONMENT", "development"),
	}

	if host := os.Getenv("FLUENTD_HOST"); host != "" {
		cfg.Fluentd = &FluentdConfig{
			Host:        host,
			Port:        intOr("FLUENTD_PORT", 24224),
			TagPrefix:   envOr("FLUENTD_TAG_PREFIX", "karlo"),
			Async:       envOr("FLUENTD_ASYNC", "true") != "false",
			BufferLimit: intOr("FLUENTD_BUFFER_LIMIT", 8*1024*1024),
			Timeout:     durationOr("FLUENTD_TIMEOUT", 3*time.Second),
		}
	}

	Init(cfg)
}

// Close flushes and releases any Fluentd connection. Services call it during
// shutdown so buffered records are not lost.
func Close() {
	closersMu.Lock()
	defer closersMu.Unlock()

	for _, c := range closers {
		c.Close()
	}
	closers = nil
}

var (
	closersMu sync.Mutex
	closers   []interface{ Close() }
)

func registerCloser(c interface{ Close() }) {
	closersMu.Lock()
	defer closersMu.Unlock()
	closers = append(closers, c)
}

// WithContext attaches a logger carrying request-scoped fields (request id,
// user id) so handlers do not have to thread them through every call.
func WithContext(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// From returns the request-scoped logger, falling back to the default.
func From(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

// fanoutHandler writes each record to every configured sink.
//
// A failing sink does not stop the others: if Fluentd is down mid-run, stdout
// must keep working.
type fanoutHandler struct {
	handlers []slog.Handler
}

func (f *fanoutHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range f.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (f *fanoutHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range f.handlers {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		// Each handler gets its own clone: handlers may consume the record's
		// attribute iterator, and sharing one would leave later sinks empty.
		_ = h.Handle(ctx, r.Clone())
	}
	return nil
}

func (f *fanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Handler, 0, len(f.handlers))
	for _, h := range f.handlers {
		out = append(out, h.WithAttrs(attrs))
	}
	return &fanoutHandler{handlers: out}
}

func (f *fanoutHandler) WithGroup(name string) slog.Handler {
	out := make([]slog.Handler, 0, len(f.handlers))
	for _, h := range f.handlers {
		out = append(out, h.WithGroup(name))
	}
	return &fanoutHandler{handlers: out}
}

func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func intOr(key string, fallback int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func durationOr(key string, fallback time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
