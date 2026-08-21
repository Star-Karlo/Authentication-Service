package authctx

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	// authorizationMD carries the end user's token on service-to-service calls,
	// so the callee can apply the same authorisation the caller would.
	authorizationMD = "authorization"
	// serviceTokenMD carries the calling service's own credential. This is what
	// distinguishes "the business service is asking" from "someone reached the
	// internal port". It is checked independently of the user token.
	serviceTokenMD = "x-karlo-service-token"
	// serviceNameMD is informational, for logs and metrics.
	serviceNameMD = "x-karlo-service"
)

// UnaryServerInterceptor authenticates inbound gRPC calls.
//
// Two things are checked. First the service token, which must match one of the
// accepted internal credentials: the gRPC ports are for services, not for the
// public. Then, if the call carries an end-user token, the principal is
// extracted so the handler can scope its answer to that user.
//
// A call with a valid service token but no user token is allowed through with
// no principal. That is the right default for genuinely internal traffic such
// as a cron job, and handlers that need a user must say so themselves.
func UnaryServerInterceptor(v *Verifier, acceptedServiceTokens []string) grpc.UnaryServerInterceptor {
	accepted := make(map[string]struct{}, len(acceptedServiceTokens))
	for _, t := range acceptedServiceTokens {
		if t != "" {
			accepted[t] = struct{}{}
		}
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if isHealthCheck(info.FullMethod) {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		if len(accepted) > 0 {
			if !hasAccepted(md.Get(serviceTokenMD), accepted) {
				return nil, status.Error(codes.Unauthenticated, "invalid service token")
			}
		}

		if tokens := md.Get(authorizationMD); len(tokens) > 0 && v != nil {
			raw := stripBearer(tokens[0])
			if principal, err := v.Verify(raw); err == nil {
				ctx = WithPrincipal(ctx, principal)
			}
			// A user token that fails verification is not fatal here: the
			// service token already authorised the call, and handlers that
			// require a principal will reject the request themselves. Failing
			// hard would break internal calls made on behalf of an expired
			// session, such as a delayed notification fan-out.
		}

		return handler(ctx, req)
	}
}

// UnaryClientInterceptor attaches this service's credential, and forwards the
// end user's token when the call is made on behalf of a request.
func UnaryClientInterceptor(serviceName, serviceToken string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = metadata.AppendToOutgoingContext(ctx,
			serviceTokenMD, serviceToken,
			serviceNameMD, serviceName,
		)
		if raw, ok := OutgoingToken(ctx); ok {
			ctx = metadata.AppendToOutgoingContext(ctx, authorizationMD, "Bearer "+raw)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

type outgoingTokenKey struct{}

// WithOutgoingToken marks a context so that downstream gRPC calls carry the end
// user's token. HTTP middleware sets this after authenticating a request.
func WithOutgoingToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, outgoingTokenKey{}, token)
}

// OutgoingToken returns the end-user token to forward, if any.
func OutgoingToken(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(outgoingTokenKey{}).(string)
	return t, ok && t != ""
}

func hasAccepted(got []string, accepted map[string]struct{}) bool {
	for _, g := range got {
		if _, ok := accepted[g]; ok {
			return true
		}
	}
	return false
}

func stripBearer(s string) string {
	if len(s) > 7 && (s[:7] == "Bearer " || s[:7] == "bearer ") {
		return s[7:]
	}
	return s
}

func isHealthCheck(method string) bool {
	return method == "/grpc.health.v1.Health/Check" || method == "/grpc.health.v1.Health/Watch"
}
