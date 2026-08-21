// Package middleware holds HTTP middleware specific to this service.
package middleware

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/platform/authctx"
)

// RequestIDHeader is the correlation header. If the caller supplies one it is
// preserved, so a request can be traced across all four services.
const RequestIDHeader = "X-Request-Id"

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

		// Make the end user's token available to outbound gRPC calls made while
		// serving this request, so downstream services see the same principal.
		if token := authctx.ExtractToken(c); token != "" {
			c.Request = c.Request.WithContext(
				authctx.WithOutgoingToken(c.Request.Context(), token),
			)
		}

		c.Next()

		attrs := []any{
			"request_id", requestID,
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"duration_ms", time.Since(start).Milliseconds(),
			"ip", c.ClientIP(),
		}
		if p, ok := authctx.Gin(c); ok {
			attrs = append(attrs, "user_id", p.UserID, "role", p.Role)
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
