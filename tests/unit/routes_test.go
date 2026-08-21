package unit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/karlo/authentication-service/internal/config"
	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/karlo/authentication-service/internal/routes"
)

// buildRouter constructs the HTTP surface with no database behind it.
//
// The handlers are nil, which is safe because every test here exercises routing
// and middleware: the requests are rejected before a handler is reached. That is
// the point — it lets the routing table and the auth wiring be tested without
// standing up Postgres.
func buildRouter(t *testing.T, environment string) http.Handler {
	t.Helper()

	verifier, err := authctx.NewVerifier(testPublicKeyPEM(t))
	if err != nil {
		t.Fatalf("could not build verifier: %v", err)
	}

	return routes.Setup(routes.Deps{
		Config: &config.Config{
			Environment:        environment,
			CORSAllowedOrigins: []string{"http://localhost:5173"},
		},
		Verifier: verifier,
	})
}

func testPublicKeyPEM(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generate a key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("could not marshal the public key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestHealthEndpoint(t *testing.T) {
	router := buildRouter(t, "development")

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /health = %d, want 200", rec.Code)
	}
}

// TestSwaggerServedOutsideProduction confirms the API browser is reachable in
// development, which is where it is useful.
func TestSwaggerServedOutsideProduction(t *testing.T) {
	router := buildRouter(t, "development")

	req := httptest.NewRequest(http.MethodGet, "/swagger/index.html", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code == http.StatusNotFound {
		t.Error("the Swagger UI should be served in development")
	}
}

// TestSwaggerHiddenInProduction is the half that matters for security. The
// document describes every endpoint, its parameters and its response shapes,
// which is precisely the reconnaissance an attacker would otherwise have to
// guess at.
func TestSwaggerHiddenInProduction(t *testing.T) {
	router := buildRouter(t, "production")

	for _, path := range []string{"/swagger/index.html", "/swagger/doc.json"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s in production = %d, want 404", path, rec.Code)
		}
	}
}

// TestProtectedRoutesRejectAnonymousRequests walks the authenticated surface and
// asserts every route refuses a request with no credential.
//
// This is the regression test for the monolith's most consequential shape: a
// route registered outside the protected group, or one whose handler read the
// token context without checking it first, panicked or served data.
func TestProtectedRoutesRejectAnonymousRequests(t *testing.T) {
	router := buildRouter(t, "development")

	protected := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/auth/me"},
		{http.MethodPost, "/api/v1/auth/logout"},
		{http.MethodPost, "/api/v1/auth/logout-all"},
		{http.MethodPost, "/api/v1/auth/change-password"},
		{http.MethodPost, "/api/v1/auth/register-member"},
		{http.MethodGet, "/api/v1/users"},
		{http.MethodGet, "/api/v1/users/00000000-0000-0000-0000-000000000000"},
		{http.MethodPut, "/api/v1/users/me"},
		{http.MethodPut, "/api/v1/users/00000000-0000-0000-0000-000000000000"},
		{http.MethodPut, "/api/v1/users/00000000-0000-0000-0000-000000000000/suspend"},
		{http.MethodPut, "/api/v1/users/00000000-0000-0000-0000-000000000000/permission"},
		{http.MethodDelete, "/api/v1/users/00000000-0000-0000-0000-000000000000"},
	}

	for _, route := range protected {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("= %d, want 401 for an unauthenticated request", rec.Code)
			}
		})
	}
}

// TestGarbageTokensAreRejected covers the shapes a hostile caller supplies.
// None may reach a handler, and none may panic.
func TestGarbageTokensAreRejected(t *testing.T) {
	router := buildRouter(t, "development")

	tokens := []struct{ name, value string }{
		{"empty bearer", "Bearer "},
		{"not a jwt", "Bearer nonsense"},
		{"two segments", "Bearer aaa.bbb"},
		{"unsigned alg none", "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."},
		{"bare token, no scheme", "just-a-string"},
		// The monolith treated any 32-character string as a valid static token.
		{"32 characters", "OzLm6oJRwxmHFRdrd9InZPzazChw3xf2"},
	}

	for _, tc := range tokens {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
			req.Header.Set("Authorization", tc.value)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("= %d, want 401", rec.Code)
			}
		})
	}
}

// TestPublicRoutesAreReachable confirms the unauthenticated surface is exactly
// what it should be: a caller with no token can reach login and registration,
// and nothing else.
func TestPublicRoutesAreReachable(t *testing.T) {
	router := buildRouter(t, "development")

	public := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/auth/login"},
		{http.MethodPost, "/api/v1/auth/register"},
		{http.MethodPost, "/api/v1/auth/refresh"},
		{http.MethodGet, "/api/v1/auth/check-available/email"},
	}

	for _, route := range public {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			// These reach a nil handler and panic, which gin.Recovery turns
			// into a 500. The assertion that matters is that they were NOT
			// turned away at the door with a 401.
			if rec.Code == http.StatusUnauthorized {
				t.Errorf("= 401; this route should not require a token")
			}
			if rec.Code == http.StatusNotFound {
				t.Errorf("= 404; this route is not registered")
			}
		})
	}
}

// TestCORSRejectsUnlistedOrigins is the regression test for cors.Default(),
// which the monolith used: it allowed every origin on a credentialed API, so
// any site could drive a logged-in user's browser against it.
func TestCORSRejectsUnlistedOrigins(t *testing.T) {
	router := buildRouter(t, "development")

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/auth/login", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if allowed := rec.Header().Get("Access-Control-Allow-Origin"); allowed != "" {
		t.Errorf("an unlisted origin was allowed: %q", allowed)
	}

	// The configured origin must still work.
	req = httptest.NewRequest(http.MethodOptions, "/api/v1/auth/login", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if allowed := rec.Header().Get("Access-Control-Allow-Origin"); allowed != "http://localhost:5173" {
		t.Errorf("the configured origin was not allowed, got %q", allowed)
	}
}

// TestRequestIDIsAssigned confirms the correlation header, without which a
// request cannot be followed across four services.
func TestRequestIDIsAssigned(t *testing.T) {
	router := buildRouter(t, "development")

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Header().Get("X-Request-Id") == "" {
		t.Error("no X-Request-Id was assigned")
	}

	// A caller-supplied id must be preserved rather than replaced, so a trace
	// started upstream survives.
	const supplied = "trace-from-the-gateway"
	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Request-Id", supplied)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-Id"); got != supplied {
		t.Errorf("X-Request-Id = %q, want the supplied %q", got, supplied)
	}
}
