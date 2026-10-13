package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"idp/internal/keys"
)

func mustHash(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

// fakeStore is an in-memory auth.Store for tests.
type fakeStore struct {
	users map[string]*User
}

func (f fakeStore) GetUserByUsername(_ context.Context, username string) (*User, error) {
	u, ok := f.users[username]
	if !ok {
		return nil, errors.New("not found")
	}
	return u, nil
}

func TestAuthenticate(t *testing.T) {
	store := fakeStore{users: map[string]*User{
		"admin": {UserID: "u1", Username: "admin", PasswordHash: mustHash(t, "correct"), Role: "admin"},
	}}

	tests := []struct {
		name     string
		username string
		password string
		wantErr  bool
	}{
		{"success", "admin", "correct", false},
		{"wrong password", "admin", "wrong", true},
		{"unknown user", "ghost", "correct", true},
		{"unknown user wrong password", "ghost", "wrong", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Authenticate(context.Background(), store, tt.username, tt.password)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Authenticate err = %v, wantErr = %v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("expected ErrInvalidCredentials, got %v", err)
			}
		})
	}
}

// TestIssueAndVerify does a full sign -> verify round trip with the
// standard golang-jwt parser and asserts every Zero-Trust claim.
func TestIssueAndVerify(t *testing.T) {
	privateKey, err := keys.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signKey, err := keys.New(privateKey)
	if err != nil {
		t.Fatalf("keys.New: %v", err)
	}

	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	issuer := &Issuer{
		Key:      privateKey,
		Kid:      signKey.Kid,
		Issuer:   "http://idp:8080",
		Audience: "zerotrust-api-gateway",
		TTL:      15 * time.Minute,
	}

	user := &User{UserID: "11111111-1111-4111-8111-111111111111", Username: "admin", Role: "admin"}
	token, expiresAt, err := issuer.Issue(user, "dev-phone-42", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !expiresAt.Equal(now.Add(15 * time.Minute)) {
		t.Fatalf("expiresAt = %v, want %v", expiresAt, now.Add(15*time.Minute))
	}

	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		if t.Header["kid"] != signKey.Kid {
			return nil, errors.New("kid header mismatch")
		}
		return &signKey.Private.PublicKey, nil
	}, jwt.WithIssuer("http://idp:8080"), jwt.WithAudience("zerotrust-api-gateway"), jwt.WithExpirationRequired(), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("ParseWithClaims: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("token not valid")
	}

	if claims.Subject != user.UserID {
		t.Fatalf("sub = %q, want %q", claims.Subject, user.UserID)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
		t.Fatalf("roles = %v, want [admin]", claims.Roles)
	}
	if claims.DeviceID != "dev-phone-42" {
		t.Fatalf("device_id = %q", claims.DeviceID)
	}
}

// TestIssueRejectsWrongSigningKey ensures a token signed by one key fails
// verification under a different public key (the gateway would 401).
func TestIssueRejectsWrongSigningKey(t *testing.T) {
	keyA, _ := keys.GeneratePrivateKey()
	keyB, _ := keys.GeneratePrivateKey()
	signA, _ := keys.New(keyA)
	issuer := &Issuer{Key: keyA, Kid: signA.Kid, Issuer: "i", Audience: "a", TTL: time.Minute}

	token, _, err := issuer.Issue(&User{UserID: "u", Role: "admin"}, "d", time.Now())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (any, error) {
		return &keyB.PublicKey, nil
	})
	if err == nil {
		t.Fatal("expected verification to fail with the wrong key")
	}
}
