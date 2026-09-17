package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSessionCookiesArePinnedToTheSharedDomain(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &sessionCookies{domain: ".karlo.id", maxAge: 2592000}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	s.set(c, "rt-secret")

	got := strings.Join(w.Header().Values("Set-Cookie"), "\n")
	for _, want := range []string{
		"karlo_rt=rt-secret", "Domain=karlo.id", "Path=/", "Max-Age=2592000", "HttpOnly", "Secure", "SameSite=Lax",
		"karlo_session=1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("Set-Cookie lacks %q:\n%s", want, got)
		}
	}
	// The marker is the one cookie a page may read.
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "karlo_session=") && strings.Contains(line, "HttpOnly") {
			t.Fatal("the marker must be readable by the page")
		}
	}

	// A nil receiver — no shared domain configured — sets nothing.
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	var none *sessionCookies
	none.set(c2, "x")
	if len(w2.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("no cookie domain must mean no cookies")
	}
}

func TestRefreshTokenIsReadFromTheCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &sessionCookies{domain: ".karlo.id", maxAge: 10}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	c.Request.AddCookie(&http.Cookie{Name: refreshCookie, Value: "from-cookie"})
	if got := s.fromCookie(c); got != "from-cookie" {
		t.Fatalf("fromCookie = %q", got)
	}
}
