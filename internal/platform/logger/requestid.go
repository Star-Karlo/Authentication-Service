package logger

import (
	"context"
	"log/slog"
)

// One request id, everywhere it goes.
//
// A request enters at the console's HTTP edge, fans out over gRPC to two or
// three services, and each of those logs on its own. Without a shared id,
// tracing one failed order across four log groups means matching
// timestamps by eye. So the HTTP middleware mints or accepts an id, puts it
// in the context, the gRPC client sends it as metadata, the gRPC server
// puts it back in the context, and this handler stamps request_id on every
// record logged with a context — slog.InfoContext and friends — in any of
// them. Records logged without a context (slog.Info) carry no id, which is
// why the codebase prefers the Context variants on request paths.

type requestIDKey struct{}

// MetadataKey is the gRPC metadata key the id travels under, and the HTTP
// header, lower-cased as gRPC requires.
const MetadataKey = "x-request-id"

// WithRequestID returns a context carrying the id.
func WithRequestID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID returns the id in the context, or "".
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// requestIDHandler adds request_id from the context to each record.
type requestIDHandler struct {
	next slog.Handler
}

func (h *requestIDHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

func (h *requestIDHandler) Handle(ctx context.Context, r slog.Record) error {
	if id := RequestID(ctx); id != "" {
		r.AddAttrs(slog.String("request_id", id))
	}
	return h.next.Handle(ctx, r)
}

func (h *requestIDHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &requestIDHandler{next: h.next.WithAttrs(attrs)}
}

func (h *requestIDHandler) WithGroup(name string) slog.Handler {
	return &requestIDHandler{next: h.next.WithGroup(name)}
}
