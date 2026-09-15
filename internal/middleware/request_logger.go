// Package middleware holds HTTP middleware specific to this service.
package middleware

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/karlo/authentication-service/internal/platform/logger"
)

// RequestIDHeader is the correlation header. If the caller supplies one it is
// preserved, so a request can be traced across all four services.
const RequestIDHeader = "X-Request-Id"

// quietPaths are logged only when they fail.
//
// The load balancer polls /health every 30 seconds, and the container health
// check does the same. Across four services that is roughly 350,000 log lines a
// month saying nothing happened — and CloudWatch charges per GB ingested with
// no free tier beyond the first 5 GB, so it is noise you pay for twice: once to
// ingest and once to store.
//
// A failing health check is still logged, which is the only time it carries
// information.
var quietPaths = map[string]bool{
	"/health": true,
	"/ready":  true,
}

// RequestLogger emits one structured line per request and assigns a request id.
//
// It deliberately does not log request bodies. This service handles passwords
// on nearly every endpoint, and a body-logging middleware is the most common
// way credentials end up in a log aggregator.
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		requestID := c.GetHeader(RequestIDHeader)
		if requestID == "" {
			requestID = uuid.NewString()
		}
		c.Set("requestID", requestID)
		c.Header(RequestIDHeader, requestID)
		// Into the context: every slog.*Context line in this request and
		// every gRPC call it makes carries the same id. See logger.RequestID.
		c.Request = c.Request.WithContext(logger.WithRequestID(c.Request.Context(), requestID))

		// Make the end user's token available to outbound gRPC calls made while
		// serving this request, so downstream services see the same principal.
		if token := authctx.ExtractToken(c); token != "" {
			c.Request = c.Request.WithContext(
				authctx.WithOutgoingToken(c.Request.Context(), token),
			)
		}

		c.Next()

		// A successful poll of a health endpoint tells nobody anything. Log it
		// only when it fails.
		if quietPaths[c.Request.URL.Path] && c.Writer.Status() < 400 {
			return
		}

		attrs := []any{
			"request_id", requestID,
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"duration_ms", time.Since(start).Milliseconds(),
			"ip", c.ClientIP(),
		}
		if p, ok := authctx.Gin(c); ok {
			// Role is a method, not a field. Passing it uncalled handed slog a
			// func value, which it cannot encode — every authenticated request
			// logged `"role":"!ERROR:json: unsupported type: func() string"`
			// instead of the role, exactly when the log was being read to work
			// out why a request was refused.
			attrs = append(attrs, "user_id", p.UserID, "role", p.Role())
		}

		switch {
		case c.Writer.Status() >= 500:
			slog.Error("request failed", append(attrs, "errors", c.Errors.String())...)
		case c.Writer.Status() >= 400:
			slog.Warn("request rejected", attrs...)
		default:
			slog.Info("request", attrs...)
		}
	}
}
