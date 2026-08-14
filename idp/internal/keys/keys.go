// Package keys manages the IdP's RSA signing key.
//
// The private key is loaded from the environment (injected via the
// git-crypt-encrypted .env) and is never hardcoded or persisted to disk by
// the service. The public key is derived in memory, so only one secret must
// be provisioned. The JWKS "kid" is the RFC 7638 thumbprint of the public
// key: self-describing, stable across restarts, and needing no configuration.
package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
)

// Key is the in-memory RSA signing identity. The private half never leaves
// the process; the public half is served to the API Gateway via JWKS.
type Key struct {
	Private *rsa.PrivateKey
	// Kid is the RFC 7638 thumbprint of the public key.
	Kid string
}

// LoadPrivateKey parses a PEM-encoded RSA private key (PKCS#1 "RSA PRIVATE
// KEY" or PKCS#8 "PRIVATE KEY" blocks are both accepted).
func LoadPrivateKey(pemString string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemString)))
	if block == nil {
		return nil, fmt.Errorf("keys: no PEM block found in supplied private key")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("keys: PKCS#8 key is not an RSA key")
		}
		return rsaKey, nil
	}
	return nil, fmt.Errorf("keys: failed to parse PEM block as PKCS#1 or PKCS#8 RSA private key")
}

// GeneratePrivateKey creates a fresh 2048-bit RSA keypair. 2048 bits is the
// pragmatic floor for RS256: secure for a POC and fast to sign with.
func GeneratePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// PrivateKeyToPEM encodes the key as a PKCS#1 PEM block, suitable for
// pasting into .env as IDP_RSA_PRIVATE_KEY.
func PrivateKeyToPEM(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

// New wraps a loaded private key and derives its thumbprint-based kid.
func New(private *rsa.PrivateKey) (*Key, error) {
	kid, err := Thumbprint(&private.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Key{Private: private, Kid: kid}, nil
}

// PublicJWK returns the public half of the key as a JWK map. The "e" (public
// exponent) and "n" (modulus) fields are base64url-encoded without padding,
// per RFC 7517.
func (k *Key) PublicJWK() map[string]string {
	pub := &k.Private.PublicKey
	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": k.Kid,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// Thumbprint computes the RFC 7638 JWK thumbprint of the public key:
// SHA-256 over the canonical {"e","kty","n"} JSON (keys in lexicographic
// order, no whitespace), base64url-encoded without padding.
func Thumbprint(pub *rsa.PublicKey) (string, error) {
	canonical, err := json.Marshal(struct {
		E   string `json:"e"`
		Kty string `json:"kty"`
		N   string `json:"n"`
	}{
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
	})
	if err != nil {
		return "", fmt.Errorf("keys: failed to marshal canonical JWK: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
