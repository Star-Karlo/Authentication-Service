package logger

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestRequestIDStampedFromContext(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(&requestIDHandler{next: slog.NewJSONHandler(&buf, nil)})

	ctx := WithRequestID(context.Background(), "req-123")
	l.InfoContext(ctx, "with id")
	l.Info("without id")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines", len(lines))
	}
	if !strings.Contains(lines[0], `"request_id":"req-123"`) {
		t.Fatalf("first line lacks the id: %s", lines[0])
	}
	if strings.Contains(lines[1], "request_id") {
		t.Fatalf("second line should carry no id: %s", lines[1])
	}
	if RequestID(context.Background()) != "" {
		t.Fatal("empty context must yield an empty id")
	}
}
