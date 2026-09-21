package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// .env.example documents `http://localhost:8088/dashboard?token=<value>` as the
// way a human opens the dashboard when TELEMETRY_READ_TOKEN is set. That has to
// actually work, and it has to leave the token behind: a token that stays in the
// URL ends up in the address bar, the browser history and every Referer header
// the page sends.

func readAuthServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg := testConfig()
	cfg.ReadToken = readToken
	return newTestServer(t, cfg, nil, nil)
}

// noRedirect returns a client that reports a redirect instead of following it,
// and keeps no cookie jar, so each step of the sign-in is observable.
func noRedirect(server *httptest.Server) *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     server.Client().Transport,
	}
}

func TestDashboardTokenIsExchangedForACookie(t *testing.T) {
	server := readAuthServer(t)
	client := noRedirect(server)

	get := func(url string) *http.Response {
		t.Helper()
		response, err := client.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		return response
	}

	// No credential at all: the dashboard is not served.
	response := get(server.URL + "/dashboard")
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", response.StatusCode)
	}
	response.Body.Close()

	// The documented URL: a redirect that sets the cookie.
	response = get(server.URL + "/dashboard?token=" + readToken)
	response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("valid token: status = %d, want 302", response.StatusCode)
	}
	if location := response.Header.Get("Location"); strings.Contains(location, readToken) {
		t.Errorf("redirect target still carries the token: %q", location)
	} else if !strings.Contains(location, "/dashboard") {
		t.Errorf("redirect target = %q, want the dashboard", location)
	}

	cookies := response.Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookie was set, so the browser would stay unauthenticated")
	}
	cookie := cookies[0]
	if cookie.Name != readTokenCookie || cookie.Value != readToken {
		t.Errorf("cookie = %s=%s, want %s=<read token>", cookie.Name, cookie.Value, readTokenCookie)
	}
	if !cookie.HttpOnly {
		t.Error("the cookie is readable from JavaScript, so any injected script could exfiltrate the audit trail")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict (a cross-site request must not carry it)", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Errorf("cookie path = %q, want /", cookie.Path)
	}

	// And the cookie works for the API calls the dashboard makes.
	request, err := http.NewRequest(http.MethodGet, server.URL+"/v1/audit/summary", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(cookie)
	authed, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("cookie request: %v", err)
	}
	authed.Body.Close()
	if authed.StatusCode != http.StatusOK {
		t.Errorf("with the cookie: status = %d, want 200", authed.StatusCode)
	}
}

func TestDashboardRejectsAWrongTokenWithoutSettingACookie(t *testing.T) {
	server := readAuthServer(t)

	response, err := noRedirect(server).Get(server.URL + "/dashboard?token=not-the-token")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", response.StatusCode)
	}
	if len(response.Cookies()) != 0 {
		t.Error("a wrong token was exchanged for a cookie")
	}
}

// A query-string token is for a human opening a page, not for an API caller: a
// token in a query string is exactly what gets written into access logs.
func TestAPIPathsDoNotAcceptATokenInTheQueryString(t *testing.T) {
	server := readAuthServer(t)

	for _, path := range []string{
		"/v1/audit/summary?token=" + readToken,
		"/v1/audit/events?token=" + readToken,
	} {
		response, _ := noRedirect(server).Get(server.URL + path)
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", path, response.StatusCode)
		}
		if len(response.Cookies()) != 0 {
			t.Errorf("%s: an API request was answered with a cookie", path)
		}
	}
}

// Behind TLS (or a terminating proxy) the cookie must be Secure, or a browser
// would send the audit-trail credential over plain HTTP.
func TestSignInCookieIsSecureBehindTLS(t *testing.T) {
	server := readAuthServer(t)

	request, err := http.NewRequest(http.MethodGet, server.URL+"/dashboard?token="+readToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Forwarded-Proto", "https")

	response, err := noRedirect(server).Do(request)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer response.Body.Close()

	cookies := response.Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookie was set")
	}
	if !cookies[0].Secure {
		t.Error("the sign-in cookie is not Secure on an HTTPS connection")
	}
}

// With no read token configured, reads are open and the token route is inert.
func TestSignInIsInertWithoutAReadToken(t *testing.T) {
	server := newTestServer(t, nil, nil, nil)

	response, err := noRedirect(server).Get(server.URL + "/dashboard?token=anything")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (reads are open when no token is configured)", response.StatusCode)
	}
}
