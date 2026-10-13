// Package jwtauth verifies the RS256 JWTs that the Identity Provider (Person 1)
// issues, against the public keys it publishes at /.well-known/jwks.json.
//
// Why the service verifies the token the gateway already verified
// (docs/flow.md §2 has the gateway do it): this is a Zero-Trust architecture.
// "The perimeter checked it" is exactly the assumption that turns one
// compromised ingress into a fully trusted internal caller. The check is
// cheap — one signature verification against a cached public key — and it is
// the difference between trusting the caller and trusting the network path.
//
// Security properties, each of which is a test:
//
//   - Only RS256 is accepted. `alg: none` and an HS256 token signed with the
//     public key as an HMAC secret (algorithm confusion) are both refused by
//     pinning the expected method rather than reading it from the header.
//   - The key is selected by `kid`; an unknown `kid` triggers a re-fetch, and
//     re-fetches are throttled so a flood of unknown ids cannot be turned into
//     a flood of requests to the IdP.
//   - A cached key set is used until it expires. Once it has expired and the
//     IdP cannot be reached, verification fails closed (a 503, not a permit):
//     being unable to check a signature is not a reason to accept it.
package jwtauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Sentinel errors, mapped by the API layer onto distinct HTTP responses and
// distinct audit reasons.
var (
	// ErrInvalidToken is a token that is present but not acceptable
	// (malformed, wrong signature, unknown key, wrong issuer/audience).
	ErrInvalidToken = errors.New("token invalid")
	// ErrTokenExpired is a token that was valid and is not any more. It is
	// separate because "the session expired" and "someone is forging tokens"
	// are different incidents.
	ErrTokenExpired = errors.New("token expired")
	// ErrMissingToken is a request with no bearer credential.
	ErrMissingToken = errors.New("token missing")
	// ErrVerificationUnavailable is a key set that could not be obtained or
	// refreshed. The caller must fail closed with a 503 (the guard is down),
	// never with a permit.
	ErrVerificationUnavailable = errors.New("verification unavailable")
)

// Claims are the token claims this service relies on.
//
// `sub` is the authenticated user (the sender binding is checked against it)
// and `roles` drives the audit record and the admin override; `device_id` is
// carried into the audit detail because docs/flow.md requires the claim and a
// transfer is worth attributing to a device.
type Claims struct {
	Roles    []string `json:"roles"`
	DeviceID string   `json:"device_id"`
	jwt.RegisteredClaims
}

// Verifier verifies tokens against a cached JWKS document.
type Verifier struct {
	jwksURL     string
	issuer      string
	audience    string
	skew        time.Duration
	cacheTTL    time.Duration
	kidThrottle time.Duration
	client      *http.Client
	now         func() time.Time

	mu           sync.RWMutex
	keys         map[string]*rsa.PublicKey
	fetchedAt    time.Time
	lastKidFetch time.Time
}

// Options configure a Verifier.
type Options struct {
	JWKSURL     string
	Issuer      string
	Audience    string
	ClockSkew   time.Duration
	CacheTTL    time.Duration
	KidThrottle time.Duration
	HTTPClient  *http.Client
	Now         func() time.Time
}

// New builds a Verifier. Nothing is fetched here: a service that cannot reach
// the IdP at startup still boots and reports unready-ish behaviour per request
// instead of crash-looping, and callers get a clear per-request error.
func New(options Options) (*Verifier, error) {
	if strings.TrimSpace(options.JWKSURL) == "" {
		return nil, errors.New("jwtauth: a JWKS URL is required")
	}
	verifier := &Verifier{
		jwksURL:     options.JWKSURL,
		issuer:      options.Issuer,
		audience:    options.Audience,
		skew:        options.ClockSkew,
		cacheTTL:    options.CacheTTL,
		kidThrottle: options.KidThrottle,
		client:      options.HTTPClient,
		now:         options.Now,
		keys:        map[string]*rsa.PublicKey{},
	}
	if verifier.client == nil {
		verifier.client = &http.Client{Timeout: 5 * time.Second}
	}
	if verifier.cacheTTL <= 0 {
		verifier.cacheTTL = 5 * time.Minute
	}
	if verifier.kidThrottle <= 0 {
		verifier.kidThrottle = 10 * time.Second
	}
	if verifier.now == nil {
		verifier.now = time.Now
	}
	return verifier, nil
}

// Verify checks the signature, the standard time claims, the issuer and the
// audience, and returns the claims.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	token := strings.TrimSpace(raw)
	if token == "" {
		return nil, ErrMissingToken
	}

	keyID := keyIDFromToken(token)

	key, err := v.key(ctx, keyID)
	if err != nil {
		return nil, err
	}

	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		// Pinning the algorithm here is what defeats `alg: none` and HS256
		// confusion: the header is attacker-controlled, so it may not choose
		// how the signature is checked.
		if t.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("jwtauth: unexpected signing method %q", t.Method.Alg())
		}
		return key, nil
	}, v.parserOptions()...)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("%w: %v", ErrTokenExpired, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("%w: signature not valid", ErrInvalidToken)
	}
	if strings.TrimSpace(claims.Subject) == "" {
		// The sender binding and every audit record depend on `sub`. A token
		// without it cannot be attributed and is refused.
		return nil, fmt.Errorf("%w: the sub claim is missing", ErrInvalidToken)
	}
	return claims, nil
}

func (v *Verifier) parserOptions() []jwt.ParserOption {
	options := []jwt.ParserOption{jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired()}
	if v.skew > 0 {
		options = append(options, jwt.WithLeeway(v.skew))
	}
	if v.issuer != "" {
		options = append(options, jwt.WithIssuer(v.issuer))
	}
	if v.audience != "" {
		options = append(options, jwt.WithAudience(v.audience))
	}
	return options
}

// key returns the public key for the token's key id, fetching or refreshing the
// key set when necessary.
//
// The decision order is the security property: a *fresh* key set is required
// before a signature is accepted. If the key set has expired and cannot be
// refreshed, the result is ErrVerificationUnavailable (a 503) rather than a
// permit, and never a signature verified against a key that may have been
// revoked.
func (v *Verifier) key(ctx context.Context, keyID string) (*rsa.PublicKey, error) {
	if keyID == "" {
		// The IdP always sets `kid`. A token without one cannot be matched to a
		// key without trying every key in the set, which is precisely the
		// shortcut that makes key rotation unsafe.
		return nil, fmt.Errorf("%w: the token has no kid header", ErrInvalidToken)
	}

	if key, fresh := v.lookup(keyID); fresh {
		return key, nil
	}

	// A miss on a fresh cache is almost always key rotation, which is a normal
	// operation and must not be throttled. A miss on an expired cache is a
	// refresh. Both are the same call, which is itself throttled so a stream of
	// junk kids cannot be turned into a stream of requests to the IdP.
	refreshErr := v.refresh(ctx, v.kidThrottle)
	if key, fresh := v.lookup(keyID); fresh {
		return key, nil
	}
	if refreshErr != nil {
		return nil, refreshErr
	}
	if v.stale() {
		return nil, fmt.Errorf("%w: the key set is stale and could not be refreshed", ErrVerificationUnavailable)
	}
	return nil, fmt.Errorf("%w: no key in the JWKS matches kid %q", ErrInvalidToken, keyID)
}

// lookup returns a cached key, but only while the key set it came from is still
// within its TTL.
func (v *Verifier) lookup(keyID string) (*rsa.PublicKey, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	key, found := v.keys[keyID]
	if !found || v.fetchedAt.IsZero() {
		return nil, false
	}
	return key, v.now().Sub(v.fetchedAt) < v.cacheTTL
}

// stale reports whether the cached key set has outlived its TTL (or was never
// fetched).
func (v *Verifier) stale() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.fetchedAt.IsZero() || v.now().Sub(v.fetchedAt) >= v.cacheTTL
}

// refresh retrieves the JWKS document, subject to a minimum interval between
// calls. A throttled call returns nil and leaves the cache decision to the
// caller, which will then fail closed if the cache is stale.
func (v *Verifier) refresh(ctx context.Context, minInterval time.Duration) error {
	v.mu.Lock()
	if since := v.now().Sub(v.lastKidFetch); since < minInterval {
		v.mu.Unlock()
		return nil
	}
	v.lastKidFetch = v.now()
	v.mu.Unlock()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerificationUnavailable, err)
	}
	request.Header.Set("Accept", "application/json")

	response, err := v.client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: fetching %s: %v", ErrVerificationUnavailable, v.jwksURL, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("%w: %s returned %s", ErrVerificationUnavailable, v.jwksURL, response.Status)
	}

	// Bound the body: a key set is a handful of kilobytes, and reading an
	// unbounded response from another service is how one compromised dependency
	// becomes a memory exhaustion in this one.
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%w: reading %s: %v", ErrVerificationUnavailable, v.jwksURL, err)
	}

	keys, err := parseJWKS(body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerificationUnavailable, err)
	}
	if len(keys) == 0 {
		return fmt.Errorf("%w: %s contains no RSA signing keys", ErrVerificationUnavailable, v.jwksURL)
	}

	v.mu.Lock()
	v.keys = keys
	v.fetchedAt = v.now()
	v.mu.Unlock()
	return nil
}

// Refresh forces a key-set fetch, used by the readiness probe so a rotated key
// is picked up without waiting for the TTL.
func (v *Verifier) Refresh(ctx context.Context) error {
	return v.refresh(ctx, 0)
}

// KeyCount reports how many signing keys are cached. It is used by the
// readiness probe to say whether the guard has material to work with, without
// ever echoing key material.
func (v *Verifier) KeyCount() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.keys)
}

// keyIDFromToken reads the `kid` header without verifying the token. Reading an
// unverified header to *choose* a key is safe; reading it to choose an
// algorithm would not be (see Verify).
func keyIDFromToken(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(decoded, &header); err != nil {
		return ""
	}
	return strings.TrimSpace(header.Kid)
}

// jwk is one key in the document (RFC 7517).
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// parseJWKS converts the document into RSA public keys, skipping anything that
// is not an RSA signing key (an encryption key in the same set must not be
// usable to verify a signature).
func parseJWKS(body []byte) (map[string]*rsa.PublicKey, error) {
	var document struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("the JWKS document is not valid JSON: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(document.Keys))
	for _, key := range document.Keys {
		if !strings.EqualFold(key.Kty, "RSA") {
			continue
		}
		if key.Use != "" && !strings.EqualFold(key.Use, "sig") {
			continue
		}
		if key.Alg != "" && !strings.EqualFold(key.Alg, "RS256") {
			continue
		}
		if key.Kid == "" {
			continue
		}
		publicKey, err := rsaPublicKey(key)
		if err != nil {
			continue
		}
		keys[key.Kid] = publicKey
	}
	return keys, nil
}

func rsaPublicKey(key jwk) (*rsa.PublicKey, error) {
	modulus, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("jwks: bad modulus: %w", err)
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("jwks: bad exponent: %w", err)
	}
	if len(modulus) == 0 || len(exponentBytes) == 0 {
		return nil, errors.New("jwks: empty modulus or exponent")
	}

	exponent := 0
	for _, b := range exponentBytes {
		exponent = exponent<<8 | int(b)
	}
	if exponent < 3 || exponent%2 == 0 {
		return nil, fmt.Errorf("jwks: implausible exponent %d", exponent)
	}
	// A key below 2048 bits is not acceptable for signing: accept nothing
	// weaker than the IdP is configured to issue.
	if len(modulus)*8 < 2048 {
		return nil, fmt.Errorf("jwks: modulus is only %d bits", len(modulus)*8)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}, nil
}
