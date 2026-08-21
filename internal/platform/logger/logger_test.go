package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"
)

// TestFanoutReachesEverySink is the property that matters operationally: if
// Fluentd is down, stdout must still receive the line. The legacy logger had a
// single sink, so an unreachable collector meant no logs at all.
func TestFanoutReachesEverySink(t *testing.T) {
	var first, second bytes.Buffer

	h := &fanoutHandler{handlers: []slog.Handler{
		slog.NewJSONHandler(&first, &slog.HandlerOptions{Level: slog.LevelInfo}),
		slog.NewJSONHandler(&second, &slog.HandlerOptions{Level: slog.LevelInfo}),
	}}

	slog.New(h).Info("hello", "order_number", "ORD-1")

	for name, buf := range map[string]*bytes.Buffer{"first": &first, "second": &second} {
		var record map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
			t.Fatalf("%s sink did not receive valid JSON: %v (%q)", name, err, buf.String())
		}
		if record["msg"] != "hello" {
			t.Errorf("%s sink: msg = %v", name, record["msg"])
		}
		// A record whose attributes reached only the first sink is the bug this
		// test exists to catch: handlers consume the attribute iterator, so the
		// record must be cloned per sink.
		if record["order_number"] != "ORD-1" {
			t.Errorf("%s sink lost the attributes: %v", name, record)
		}
	}
}

func TestFanoutRespectsPerHandlerLevel(t *testing.T) {
	var infoSink, errorSink bytes.Buffer

	h := &fanoutHandler{handlers: []slog.Handler{
		slog.NewJSONHandler(&infoSink, &slog.HandlerOptions{Level: slog.LevelInfo}),
		slog.NewJSONHandler(&errorSink, &slog.HandlerOptions{Level: slog.LevelError}),
	}}

	slog.New(h).Info("routine")

	if infoSink.Len() == 0 {
		t.Error("the info sink should have received an info line")
	}
	if errorSink.Len() != 0 {
		t.Errorf("the error-only sink should have skipped an info line, got %q", errorSink.String())
	}
}

func TestFanoutWithAttrsPropagates(t *testing.T) {
	var buf bytes.Buffer
	h := (&fanoutHandler{handlers: []slog.Handler{
		slog.NewJSONHandler(&buf, nil),
	}}).WithAttrs([]slog.Attr{slog.String("service", "business")})

	slog.New(h).Info("started")

	var record map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if record["service"] != "business" {
		t.Errorf("service attribute did not propagate: %v", record)
	}
}

// TestAddAttrFlattening pins the shape records take on the wire. Flat, dotted
// keys index far better in a log backend than nested objects.
func TestAddAttrFlattening(t *testing.T) {
	data := map[string]interface{}{}

	addAttr(data, nil, slog.String("plain", "value"))
	addAttr(data, []string{"http"}, slog.Int("status", 500))
	addAttr(data, nil, slog.Group("db",
		slog.String("table", "orders"),
		slog.Int("rows", 3),
	))
	addAttr(data, []string{"outer"}, slog.Group("inner", slog.String("leaf", "x")))

	want := map[string]interface{}{
		"plain":            "value",
		"http.status":      int64(500),
		"db.table":         "orders",
		"db.rows":          int64(3),
		"outer.inner.leaf": "x",
	}

	for k, v := range want {
		got, ok := data[k]
		if !ok {
			t.Errorf("key %q is missing; got %v", k, data)
			continue
		}
		if got != v {
			t.Errorf("key %q = %v (%T), want %v (%T)", k, got, got, v, v)
		}
	}
}

func TestAddAttrSkipsEmpty(t *testing.T) {
	data := map[string]interface{}{}

	addAttr(data, nil, slog.Attr{})
	addAttr(data, nil, slog.Group("empty"))

	if len(data) != 0 {
		t.Errorf("empty attributes should not be shipped, got %v", data)
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":    slog.LevelDebug,
		"info":     slog.LevelInfo,
		"warn":     slog.LevelWarn,
		"warning":  slog.LevelWarn,
		"error":    slog.LevelError,
		"":         slog.LevelInfo,
		"nonsense": slog.LevelInfo,
	}
	for in, want := range cases {
		if got := parseLevel(in); got != want {
			t.Errorf("parseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestInitWithUnreachableFluentdStillLogs is the degradation guarantee: a
// service must start and log even when the collector is unreachable.
func TestInitWithUnreachableFluentdStillLogs(t *testing.T) {
	Init(Config{
		Service:     "test",
		Level:       "info",
		Environment: "test",
		Fluentd: &FluentdConfig{
			// A port nothing listens on, with async off so the dial is attempted
			// synchronously and fails during Init.
			Host:    "127.0.0.1",
			Port:    1,
			Async:   false,
			Timeout: 100 * time.Millisecond,
		},
	})
	defer Close()

	// The point is that Init returned at all and the default logger works.
	slog.Default().Info("still logging")
}

func TestContextLogger(t *testing.T) {
	var buf bytes.Buffer
	scoped := slog.New(slog.NewJSONHandler(&buf, nil)).With("request_id", "abc")

	ctx := WithContext(context.Background(), scoped)
	From(ctx).Info("scoped")

	var record map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if record["request_id"] != "abc" {
		t.Errorf("request-scoped attribute missing: %v", record)
	}

	// Without a scoped logger the default is returned, not nil.
	if From(context.Background()) == nil {
		t.Error("From should fall back to the default logger")
	}
}
