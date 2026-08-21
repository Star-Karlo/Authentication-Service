package logger

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/fluent/fluent-logger-golang/fluent"
)

// fluentdHandler is an slog.Handler that forwards records to Fluentd.
//
// The record is flattened into a map rather than shipped as a rendered line, so
// fields stay queryable at the collector: "show me every 500 from the business
// service in the last hour" is a filter, not a regex over text.
type fluentdHandler struct {
	client *fluent.Fluent
	tag    string
	level  slog.Level

	// attrs and groups accumulate through WithAttrs and WithGroup, since a
	// handler must carry the context its parent established.
	attrs  []slog.Attr
	groups []string

	// closeOnce guards Close, which may be reached from both an explicit
	// shutdown and a deferred cleanup.
	closeOnce *sync.Once
}

// newFluentdHandler dials Fluentd. A dial failure is returned so the caller can
// fall back to stdout-only rather than starting with no logging.
func newFluentdHandler(cfg FluentdConfig, service string, level slog.Level) (*fluentdHandler, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("logger: fluentd host is empty")
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	bufferLimit := cfg.BufferLimit
	if bufferLimit <= 0 {
		bufferLimit = 8 * 1024 * 1024
	}

	client, err := fluent.New(fluent.Config{
		FluentHost: cfg.Host,
		FluentPort: cfg.Port,
		// Async means a log call never blocks on the network. During a
		// collector outage records queue up to BufferLimit and are then
		// dropped, which is the correct trade: dropping logs is survivable,
		// stalling every request handler is not.
		Async:                  cfg.Async,
		BufferLimit:            bufferLimit,
		WriteTimeout:           timeout,
		Timeout:                timeout,
		MaxRetry:               3,
		AsyncReconnectInterval: 5000,
	})
	if err != nil {
		return nil, fmt.Errorf("logger: connect fluentd at %s:%d: %w", cfg.Host, cfg.Port, err)
	}

	prefix := cfg.TagPrefix
	if prefix == "" {
		prefix = "karlo"
	}

	return &fluentdHandler{
		client:    client,
		tag:       prefix + "." + service,
		level:     level,
		closeOnce: &sync.Once{},
	}, nil
}

func (h *fluentdHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

// Handle ships one record.
//
// The error is swallowed rather than returned, because slog offers no way to
// surface a handler error to the caller and a logging failure must not become
// an application failure.
func (h *fluentdHandler) Handle(_ context.Context, r slog.Record) error {
	data := map[string]interface{}{
		"level":   r.Level.String(),
		"message": r.Message,
		"time":    r.Time.UTC().Format(time.RFC3339Nano),
	}

	for _, a := range h.attrs {
		addAttr(data, h.groups, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		addAttr(data, h.groups, a)
		return true
	})

	_ = h.client.Post(h.tag, data)
	return nil
}

func (h *fluentdHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	combined := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	combined = append(combined, h.attrs...)
	combined = append(combined, attrs...)

	return &fluentdHandler{
		client:    h.client,
		tag:       h.tag,
		level:     h.level,
		attrs:     combined,
		groups:    h.groups,
		closeOnce: h.closeOnce,
	}
}

func (h *fluentdHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	groups := make([]string, 0, len(h.groups)+1)
	groups = append(groups, h.groups...)
	groups = append(groups, name)

	return &fluentdHandler{
		client:    h.client,
		tag:       h.tag,
		level:     h.level,
		attrs:     h.attrs,
		groups:    groups,
		closeOnce: h.closeOnce,
	}
}

// Close flushes buffered records and releases the connection.
func (h *fluentdHandler) Close() {
	h.closeOnce.Do(func() {
		if h.client != nil {
			_ = h.client.Close()
		}
	})
}

// addAttr flattens one attribute into the record map.
//
// Groups become dotted key prefixes rather than nested objects, because most
// log backends index flat keys far better than deep structures.
func addAttr(data map[string]interface{}, groups []string, a slog.Attr) {
	a.Value = a.Value.Resolve()

	// An empty attribute carries no information and clutters the index.
	if a.Equal(slog.Attr{}) {
		return
	}

	if a.Value.Kind() == slog.KindGroup {
		nested := a.Value.Group()
		if len(nested) == 0 {
			return
		}
		inner := groups
		if a.Key != "" {
			inner = append(append([]string{}, groups...), a.Key)
		}
		for _, sub := range nested {
			addAttr(data, inner, sub)
		}
		return
	}

	key := a.Key
	if len(groups) > 0 {
		key = strings.Join(groups, ".") + "." + key
	}
	data[key] = a.Value.Any()
}
