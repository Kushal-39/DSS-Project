package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
)

// TestThumbprintRFC7638 checks the thumbprint against the canonical test
// vector from RFC 7638 Appendix A.1. If this fails, the JWKS "kid" would not
// match the ecosystem's expectations.
func TestThumbprintRFC7638(t *testing.T) {
	n, err := base64.RawURLEncoding.DecodeString(
		"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: 65537,
	}

	got, err := Thumbprint(pub)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	if got != want {
		t.Fatalf("thumbprint mismatch:\n got %q\nwant %q", got, want)
	}
}

// TestPEMRoundTrip verifies that a generated key survives the
// generate -> PEM -> load cycle used by `genkey` and `.env`.
func TestPEMRoundTrip(t *testing.T) {
	key, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}

	pem := PrivateKeyToPEM(key)
	if !strings.Contains(pem, "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("PEM missing header: %q", pem)
	}

	loaded, err := LoadPrivateKey(pem)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if loaded.N.Cmp(key.N) != 0 {
		t.Fatal("loaded key modulus differs from original")
	}
}

// TestLoadPrivateKeyPKCS8 verifies PKCS#8 ("PRIVATE KEY") blocks are
// accepted too.
func TestLoadPrivateKeyPKCS8(t *testing.T) {
	key, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	pkcs8 := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: mustMarshalPKCS8(t, key),
	})

	if _, err := LoadPrivateKey(string(pkcs8)); err != nil {
		t.Fatalf("LoadPrivateKey(PKCS#8): %v", err)
	}
}

func mustMarshalPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return der
}

func TestLoadPrivateKeyInvalid(t *testing.T) {
	for _, input := range []string{"", "not a pem", "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"} {
		if _, err := LoadPrivateKey(input); err == nil {
			t.Fatalf("expected error for input %q", input)
		}
	}
}

// TestPublicJWK verifies the JWK fields are present, correctly encoded, and
// stable across instances derived from the same key.
func TestPublicJWK(t *testing.T) {
	key, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	k, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	jwk := k.PublicJWK()
	for _, field := range []string{"kty", "use", "alg", "kid", "n", "e"} {
		if jwk[field] == "" {
			t.Fatalf("JWK missing field %q: %v", field, jwk)
		}
	}
	if jwk["kty"] != "RSA" || jwk["alg"] != "RS256" || jwk["use"] != "sig" {
		t.Fatalf("unexpected JWK header values: %v", jwk)
	}
	if jwk["kid"] != k.Kid {
		t.Fatalf("kid mismatch: %q vs %q", jwk["kid"], k.Kid)
	}

	// n must round-trip back to the modulus.
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk["n"])
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	if new(big.Int).SetBytes(nBytes).Cmp(key.N) != 0 {
		t.Fatal("JWK modulus does not match key")
	}
}
