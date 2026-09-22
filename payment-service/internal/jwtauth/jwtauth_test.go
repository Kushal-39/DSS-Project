package jwtauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testAudience = "zerotrust-api-gateway"
	testIssuer   = "http://idp:8080"
)

// idp is a stand-in for Person 1: an RSA key pair, a JWKS document and tokens
// signed with the same key.
type idp struct {
	key     *rsa.PrivateKey
	kid     string
	server  *httptest.Server
	fetches *int64
}

func newIdP(t *testing.T) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	instance := &idp{key: key, kid: "test-key-1", fetches: new(int64)}
	instance.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(instance.fetches, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": instance.kid,
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(instance.server.Close)
	return instance
}

func (i *idp) token(t *testing.T, mutate func(claims *Claims)) string {
	t.Helper()
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    testIssuer,
			Subject:   "6f9619ff-8b86-d011-b42d-00c04fc964ff",
			Audience:  jwt.ClaimStrings{testAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
		},
		Roles:    []string{"customer"},
		DeviceID: "test-device",
	}
	if mutate != nil {
		mutate(claims)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = i.kid
	signed, err := token.SignedString(i.key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func newVerifier(t *testing.T, instance *idp, mutate func(*Options)) *Verifier {
	t.Helper()
	options := Options{
		JWKSURL:     instance.server.URL,
		Issuer:      testIssuer,
		Audience:    testAudience,
		ClockSkew:   30 * time.Second,
		CacheTTL:    5 * time.Minute,
		KidThrottle: 10 * time.Second,
	}
	if mutate != nil {
		mutate(&options)
	}
	verifier, err := New(options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return verifier
}

func TestVerifyAcceptsTheIdPsToken(t *testing.T) {
	instance := newIdP(t)
	verifier := newVerifier(t, instance, nil)

	claims, err := verifier.Verify(context.Background(), instance.token(t, nil))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "6f9619ff-8b86-d011-b42d-00c04fc964ff" {
		t.Errorf("subject = %q", claims.Subject)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "customer" {
		t.Errorf("roles = %v", claims.Roles)
	}
	if claims.DeviceID != "test-device" {
		t.Errorf("device_id = %q", claims.DeviceID)
	}
}

func TestVerifyRefusesTokensItMustRefuse(t *testing.T) {
	instance := newIdP(t)

	for name, testCase := range map[string]struct {
		token  func() string
		expect error
	}{
		"expired": {
			token: func() string {
				return instance.token(t, func(claims *Claims) {
					claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-2 * time.Hour))
					claims.IssuedAt = jwt.NewNumericDate(time.Now().Add(-3 * time.Hour))
				})
			},
			expect: ErrTokenExpired,
		},
		"wrong audience": {
			token: func() string {
				return instance.token(t, func(claims *Claims) {
					claims.Audience = jwt.ClaimStrings{"some-other-service"}
				})
			},
			expect: ErrInvalidToken,
		},
		"wrong issuer": {
			token: func() string {
				return instance.token(t, func(claims *Claims) {
					claims.Issuer = "http://evil.example"
				})
			},
			expect: ErrInvalidToken,
		},
		"missing subject": {
			token: func() string {
				return instance.token(t, func(claims *Claims) { claims.Subject = "" })
			},
			expect: ErrInvalidToken,
		},
		"not signed at all": {
			token: func() string {
				claims := &Claims{RegisteredClaims: jwt.RegisteredClaims{
					Issuer: testIssuer, Subject: "x", Audience: jwt.ClaimStrings{testAudience},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				}}
				token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
				token.Header["kid"] = instance.kid
				signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
				if err != nil {
					t.Fatalf("sign none: %v", err)
				}
				return signed
			},
			expect: ErrInvalidToken,
		},
		"signed with the public key as an HMAC secret": {
			token: func() string {
				// The classic algorithm-confusion attack: the verifier is handed
				// a token that claims HS256, using material it can read from the
				// JWKS endpoint as the shared secret.
				claims := &Claims{RegisteredClaims: jwt.RegisteredClaims{
					Issuer: testIssuer, Subject: "x", Audience: jwt.ClaimStrings{testAudience},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				}}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				token.Header["kid"] = instance.kid
				signed, err := token.SignedString(instance.key.PublicKey.N.Bytes())
				if err != nil {
					t.Fatalf("sign hmac: %v", err)
				}
				return signed
			},
			expect: ErrInvalidToken,
		},
		"unknown key id": {
			token: func() string {
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, &Claims{RegisteredClaims: jwt.RegisteredClaims{
					Issuer: testIssuer, Subject: "x", Audience: jwt.ClaimStrings{testAudience},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				}})
				token.Header["kid"] = "rotated-away"
				signed, err := token.SignedString(instance.key)
				if err != nil {
					t.Fatalf("sign: %v", err)
				}
				return signed
			},
			expect: ErrInvalidToken,
		}, "no key id": {
			token: func() string {
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, &Claims{RegisteredClaims: jwt.RegisteredClaims{
					Issuer: testIssuer, Subject: "x", Audience: jwt.ClaimStrings{testAudience},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				}})
				signed, err := token.SignedString(instance.key)
				if err != nil {
					t.Fatalf("sign: %v", err)
				}
				return signed
			},
			expect: ErrInvalidToken,
		},
		"garbage": {
			token:  func() string { return "not.a.token" },
			expect: ErrInvalidToken,
		},
		"empty": {
			token:  func() string { return "" },
			expect: ErrMissingToken,
		},
	} {
		t.Run(name, func(t *testing.T) {
			verifier := newVerifier(t, instance, nil)
			_, err := verifier.Verify(context.Background(), testCase.token())
			if !errors.Is(err, testCase.expect) {
				t.Fatalf("error = %v, want %v", err, testCase.expect)
			}
		})
	}
}

// A token signed by a different key that happens to carry a known kid must not
// verify: the signature is the check, not the header.
func TestVerifyRefusesAForgedSignature(t *testing.T) {
	instance := newIdP(t)
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	original := instance.key
	instance.key = attacker
	forged := instance.token(t, nil)
	instance.key = original

	verifier := newVerifier(t, instance, nil)
	if _, err := verifier.Verify(context.Background(), forged); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("error = %v, want ErrInvalidToken", err)
	}
}

// A guard that cannot check a credential must not wave it through.
func TestVerifyFailsClosedWhenTheKeySetIsUnavailable(t *testing.T) {
	instance := newIdP(t)
	token := instance.token(t, nil)
	instance.server.Close()

	verifier := newVerifier(t, instance, nil)
	if _, err := verifier.Verify(context.Background(), token); !errors.Is(err, ErrVerificationUnavailable) {
		t.Fatalf("error = %v, want ErrVerificationUnavailable", err)
	}
}

func TestVerifyUsesTheCachedKeySetUntilItExpires(t *testing.T) {
	instance := newIdP(t)
	token := instance.token(t, nil)
	verifier := newVerifier(t, instance, nil)

	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	afterFirst := atomic.LoadInt64(instance.fetches)

	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatalf("second Verify: %v", err)
	}
	if got := atomic.LoadInt64(instance.fetches); got != afterFirst {
		t.Errorf("a warm cache must not refetch on every request (fetches %d -> %d)", afterFirst, got)
	}

	// Within the TTL the cached keys keep working even if the IdP is gone: an
	// IdP restart must not break in-flight transfers.
	instance.server.Close()
	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatalf("a warm cache must survive an IdP outage within the TTL: %v", err)
	}

	// Once the cache is stale and the IdP cannot be reached, verification fails
	// closed rather than continuing to trust a key set of unknown age.
	stale := newVerifier(t, instance, func(options *Options) { options.CacheTTL = time.Hour })
	if err := stale.refresh(context.Background(), 0); err == nil {
		t.Fatal("a fetch against a closed server must fail")
	}
	if !stale.stale() {
		t.Fatal("a key set that was never fetched must count as stale")
	}
}

func TestUnknownKeyIDIsThrottledSoItCannotHammerTheIdP(t *testing.T) {
	instance := newIdP(t)
	verifier := newVerifier(t, instance, nil)

	// Warm the cache, so every fetch after this point is one an unknown kid
	// caused.
	if _, err := verifier.Verify(context.Background(), instance.token(t, nil)); err != nil {
		t.Fatalf("warming the cache: %v", err)
	}
	before := atomic.LoadInt64(instance.fetches)

	unknown := unknownKidToken(t, instance, "unknown-kid")
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := verifier.Verify(context.Background(), unknown); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("error = %v, want ErrInvalidToken for an unknown kid", err)
		}
	}

	// The first attempt refreshes once (the key may have rotated); the rest are
	// refused from the cache. Without this bound a stream of junk kid headers
	// becomes a denial-of-service against the IdP.
	if got := atomic.LoadInt64(instance.fetches) - before; got > 1 {
		t.Errorf("unknown kids triggered %d key-set fetches, want at most 1 (throttled)", got)
	}
}

func unknownKidToken(t *testing.T, instance *idp, kid string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, &Claims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: testIssuer, Subject: "x", Audience: jwt.ClaimStrings{testAudience},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}})
	token.Header["kid"] = kid
	signed, err := token.SignedString(instance.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func TestParseJWKSSkipsKeysThatCannotVerifyASignature(t *testing.T) {
	keys, err := parseJWKS([]byte(`{"keys":[
		{"kty":"EC","kid":"ec","use":"sig"},
		{"kty":"RSA","kid":"enc","use":"enc","n":"` + testModulus + `","e":"AQAB"},
		{"kty":"RSA","kid":"weak","use":"sig","n":"AQAB","e":"AQAB"},
		{"kty":"RSA","kid":"","use":"sig","n":"` + testModulus + `","e":"AQAB"}
	]}`))
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected every key to be skipped, got %d", len(keys))
	}

	if _, err := parseJWKS([]byte("not json")); err == nil {
		t.Error("a malformed document must be an error, not an empty key set")
	}
}

// testModulus is a 2048-bit modulus (the JWKS base64url form of a real key), so
// the "this key is too weak" path is exercised rather than the "this key is
// malformed" one.
const testModulus = "0cBBq9HmbfBwHz1uWlGr-QYdOGz0OWmxRn2pYJ5kMZ9uF1uvHvhKz6WcV3lJhQzSHkXk" +
	"g2vJpWLkRzT7Zm9cQqfSnV5YwFzKmV8sNn2LhRqTpZbYdG6cWJ4xKz3nQ1VJ8pMcS7yLrBf2XvTd9" +
	"hKzMTQn5Ybv7cWpR2jLxNqFzS3mVd9KxTb8YnJwC4pHsL2rG5tQzM7vXcK9nBfZdWjS6yRpT3mH8qN" +
	"vL5cZxKQ2bTdY7wFgJ9nMsRpX4vHzB8cT3mLqWyNd6KfXjSg7PnQrV2cZtMh4bWzY9nLpKsF5dXvRj" +
	"QwT8mHcNbY3sZxKg7Vd2LmRfT6pJnWq9cBvXsY4hKzM5rTdG8nLfQb7XjRvP2mHsNcZ9wYtKqBgT4d" +
	"VnLxR8sMfQpW3cZyJvHbT5mKdXgN9rLwSqZ2tBcYfP7sVjRhM4dXnK6mQbTyW8rLzGcJ5vNsXpR3tHf" +
	"QdM9wYkLbV7nRzXcT2sJgPm5qWfYtH8vNdQrL3xZcBjM6sTpKV9nYwRhF4dXmL2bQzJ7vGcNtS5rWyK"
