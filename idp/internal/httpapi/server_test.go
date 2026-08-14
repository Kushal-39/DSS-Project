package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"idp/internal/auth"
	"idp/internal/keys"
)

// fakeStore is an in-memory auth.Store.
type fakeStore struct {
	users map[string]*auth.User
}

func (f fakeStore) GetUserByUsername(_ context.Context, username string) (*auth.User, error) {
	u, ok := f.users[username]
	if !ok {
		return nil, errors.New("not found")
	}
	return u, nil
}

// fakePinger stands in for the pgx pool.
type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

func mustHash(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

func testServer(t *testing.T, store auth.Store, pinger pinger) (http.Handler, *keys.Key) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	privateKey, err := keys.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signKey, err := keys.New(privateKey)
	if err != nil {
		t.Fatalf("keys.New: %v", err)
	}

	issuer := &auth.Issuer{
		Key:      privateKey,
		Kid:      signKey.Kid,
		Issuer:   "http://idp:8080",
		Audience: "zerotrust-api-gateway",
		TTL:      15 * time.Minute,
	}
	return New(logger, store, issuer, signKey, pinger), signKey
}

func doJSON(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = bytes.NewBufferString(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestLoginSuccess(t *testing.T) {
	store := fakeStore{users: map[string]*auth.User{
		"admin": {UserID: "11111111-1111-4111-8111-111111111111", Username: "admin", PasswordHash: mustHash(t, "admin123"), Role: "admin"},
	}}
	h, signKey := testServer(t, store, fakePinger{})

	rec := doJSON(t, h, "POST", "/login", `{"username":"admin","password":"admin123","device_id":"phone-1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Token     string `json:"token"`
		TokenType string `json:"token_type"`
		ExpiresIn int    `json:"expires_in"`
		User      struct {
			ID       string `json:"id"`
			Username string `json:"username"`
			Role     string `json:"role"`
		} `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.TokenType != "Bearer" || resp.ExpiresIn != 900 {
		t.Fatalf("unexpected envelope: %+v", resp)
	}
	if resp.User.ID == "" || resp.User.Username != "admin" || resp.User.Role != "admin" {
		t.Fatalf("unexpected user: %+v", resp.User)
	}

	// The returned token must verify against the served public key and carry
	// the Zero-Trust claims (docs/flow.md: sub, roles, device_id).
	claims := &auth.Claims{}
	parsed, err := jwt.ParseWithClaims(resp.Token, claims, func(t *jwt.Token) (any, error) {
		return &signKey.Private.PublicKey, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("token verification failed: %v", err)
	}
	if claims.Subject != resp.User.ID {
		t.Fatalf("sub = %q, want %q", claims.Subject, resp.User.ID)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
		t.Fatalf("roles = %v", claims.Roles)
	}
	if claims.DeviceID != "phone-1" {
		t.Fatalf("device_id = %q", claims.DeviceID)
	}
}

func TestLoginGeneratedDeviceID(t *testing.T) {
	store := fakeStore{users: map[string]*auth.User{
		"customer": {UserID: "22222222-2222-4222-8222-222222222222", Username: "customer", PasswordHash: mustHash(t, "pw"), Role: "customer"},
	}}
	h, signKey := testServer(t, store, fakePinger{})

	rec := doJSON(t, h, "POST", "/login", `{"username":"customer","password":"pw"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	claims := &auth.Claims{}
	_, err := jwt.ParseWithClaims(resp.Token, claims, func(t *jwt.Token) (any, error) {
		return &signKey.Private.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.DeviceID == "" {
		t.Fatal("device_id should be generated when omitted")
	}
	if !strings.Contains(claims.DeviceID, "-") {
		t.Fatalf("generated device_id is not a UUID: %q", claims.DeviceID)
	}
}

func TestLoginFailures(t *testing.T) {
	store := fakeStore{users: map[string]*auth.User{
		"admin": {UserID: "u1", Username: "admin", PasswordHash: mustHash(t, "admin123"), Role: "admin"},
	}}
	h, _ := testServer(t, store, fakePinger{})

	tests := []struct {
		name string
		body string
		code int
	}{
		{"wrong password", `{"username":"admin","password":"nope"}`, http.StatusUnauthorized},
		{"unknown user", `{"username":"ghost","password":"admin123"}`, http.StatusUnauthorized},
		{"malformed json", `{not json`, http.StatusBadRequest},
		{"missing password", `{"username":"admin"}`, http.StatusBadRequest},
		{"missing username", `{"password":"admin123"}`, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doJSON(t, h, "POST", "/login", tt.body)
			if rec.Code != tt.code {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.code, rec.Body.String())
			}
		})
	}

	// Both auth failures must carry the same error code (no enumeration).
	wrongPw := doJSON(t, h, "POST", "/login", `{"username":"admin","password":"nope"}`)
	ghost := doJSON(t, h, "POST", "/login", `{"username":"ghost","password":"x"}`)
	if !strings.Contains(wrongPw.Body.String(), "invalid_credentials") ||
		!strings.Contains(ghost.Body.String(), "invalid_credentials") {
		t.Fatalf("expected identical invalid_credentials errors, got %q and %q",
			wrongPw.Body.String(), ghost.Body.String())
	}
}

func TestJWKS(t *testing.T) {
	store := fakeStore{users: map[string]*auth.User{}}
	h, signKey := testServer(t, store, fakePinger{})

	rec := doJSON(t, h, "GET", "/.well-known/jwks.json", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected exactly one key, got %d", len(jwks.Keys))
	}
	k := jwks.Keys[0]
	if k["kid"] != signKey.Kid || k["kty"] != "RSA" || k["alg"] != "RS256" || k["use"] != "sig" {
		t.Fatalf("unexpected JWK: %v", k)
	}
	if k["n"] == "" || k["e"] == "" {
		t.Fatalf("JWK missing modulus/exponent: %v", k)
	}
}

func TestOpenIDConfig(t *testing.T) {
	store := fakeStore{users: map[string]*auth.User{}}
	h, _ := testServer(t, store, fakePinger{})

	rec := doJSON(t, h, "GET", "/.well-known/openid-configuration", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), ".well-known/jwks.json") {
		t.Fatalf("discovery doc missing jwks_uri: %s", rec.Body.String())
	}
}

func TestHealthzAndReadyz(t *testing.T) {
	store := fakeStore{users: map[string]*auth.User{}}

	t.Run("healthy", func(t *testing.T) {
		h, _ := testServer(t, store, fakePinger{})
		if rec := doJSON(t, h, "GET", "/healthz", ""); rec.Code != http.StatusOK {
			t.Fatalf("healthz status = %d", rec.Code)
		}
		if rec := doJSON(t, h, "GET", "/readyz", ""); rec.Code != http.StatusOK {
			t.Fatalf("readyz status = %d", rec.Code)
		}
	})

	t.Run("db down", func(t *testing.T) {
		h, _ := testServer(t, store, fakePinger{err: errors.New("connection refused")})
		if rec := doJSON(t, h, "GET", "/readyz", ""); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("readyz with dead db status = %d, want 503", rec.Code)
		}
	})
}
