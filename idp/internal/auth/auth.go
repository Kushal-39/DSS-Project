// Package auth implements the IdP's core security logic: verifying
// credentials against the bcrypt hash and issuing signed RS256 JWTs using
// the community-standard golang-jwt library (no hand-rolled signing).
//
// Security properties:
//   - Identical "invalid_credentials" response whether the username or the
//     password is wrong, so the endpoint does not reveal which usernames
//     exist (user-enumeration resistance).
//   - A dummy bcrypt hash is compared when the user is not found, so
//     successful and failed lookups take similar time (timing side-channel
//     resistance).
//   - Tokens carry sub, roles (array — the Policy Engine contract in
//     docs/division.md reads input.subject.roles[_]) and device_id
//     (docs/flow.md).
package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// ErrInvalidCredentials is returned for any failed login; the same error is
// used for unknown usernames and wrong passwords.
var ErrInvalidCredentials = errors.New("invalid credentials")

// User is the subset of the credentials row needed for authentication.
type User struct {
	UserID       string
	Username     string
	PasswordHash string
	Role         string
}

// Store abstracts credential lookup so handlers can be unit-tested without
// a database.
type Store interface {
	GetUserByUsername(ctx context.Context, username string) (*User, error)
}

// dummyHash is compared against the submitted password whenever a username
// is not found, keeping timing roughly constant across user-exists and
// user-missing paths. Its plaintext is irrelevant.
const dummyHash = "$2a$10$Sfr7rOEC27E1s6XNaz.boezZusBW.ZGOAWAMCWamwuE2fgUzW2swq"

// VerifyPassword reports whether password matches the stored bcrypt hash.
func VerifyPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// Claims are the JWT payload fields. Standard claims carry identity and
// lifetime; roles and device_id are the Zero-Trust attributes the API
// Gateway and Policy Engine rely on (docs/flow.md, docs/division.md).
type Claims struct {
	jwt.RegisteredClaims
	Roles    []string `json:"roles"`
	DeviceID string   `json:"device_id"`
}

// Issuer configures token signing.
type Issuer struct {
	Key      *rsa.PrivateKey
	Kid      string
	Issuer   string
	Audience string
	TTL      time.Duration
}

// Issue builds and signs a new RS256 JWT for the given user. The token is
// signed with the process's RSA private key; signing never leaves this
// package and never touches disk.
func (iss *Issuer) Issue(user *User, deviceID string, now time.Time) (string, time.Time, error) {
	expiresAt := now.Add(iss.TTL)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss.Issuer,
			Subject:   user.UserID,
			Audience:  jwt.ClaimStrings{iss.Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			ID:        newJTI(now),
		},
		Roles:    []string{user.Role},
		DeviceID: deviceID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = iss.Kid

	signed, err := token.SignedString(iss.Key)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: failed to sign token: %w", err)
	}
	return signed, expiresAt, nil
}

// newJTI returns a unique token ID derived from the issue time. Nanosecond
// precision is sufficient uniqueness for a POC without an extra UUID
// dependency, and the jti claim keeps tokens replay-resistant in practice.
func newJTI(now time.Time) string {
	return fmt.Sprintf("%d", now.UnixNano())
}

// Authenticate resolves a username/password pair against the store and, on
// success, returns the user. Both failure modes (unknown user, wrong
// password) collapse into ErrInvalidCredentials.
func Authenticate(ctx context.Context, store Store, username, password string) (*User, error) {
	user, err := store.GetUserByUsername(ctx, username)
	if err != nil {
		// User not found: burn comparable time on the dummy hash so the
		// response latency does not reveal whether the username exists.
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
		return nil, ErrInvalidCredentials
	}

	if !VerifyPassword(password, user.PasswordHash) {
		return nil, ErrInvalidCredentials
	}
	return user, nil
}
