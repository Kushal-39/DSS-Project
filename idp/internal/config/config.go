// Package config loads and validates the IdP's runtime configuration from
// environment variables. Secrets are injected via the git-crypt-encrypted
// .env file — nothing is hardcoded, and any missing required variable kills
// the process immediately with a clear error (fail fast).
package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Config is the validated runtime configuration for the IdP service.
type Config struct {
	// DatabaseURL is the PostgreSQL connection string (Supabase).
	DatabaseURL string
	// RSAPrivateKeyPEM is the RSA private key in PEM form, loaded from
	// IDP_RSA_PRIVATE_KEY (literal "\n" escapes are expanded).
	RSAPrivateKeyPEM string
	// RSAPrivateKeyPath optionally points at a file containing the PEM key,
	// used when IDP_RSA_PRIVATE_KEY is not set (e.g. Docker secrets).
	RSAPrivateKeyPath string

	// Port is the HTTP listen port (IDP_PORT, default 8080).
	Port string
	// JWTIssuer is the "iss" claim (IDP_JWT_ISSUER).
	JWTIssuer string
	// JWTAudience is the "aud" claim (IDP_JWT_AUDIENCE).
	JWTAudience string
	// JWTTTL is the token lifetime (IDP_JWT_TTL, default 15m).
	JWTTTL time.Duration
}

// Load reads the environment and returns a validated Config.
//
// Required variables (process exits on failure):
//   - DATABASE_URL
//   - IDP_RSA_PRIVATE_KEY or IDP_RSA_PRIVATE_KEY_PATH
//
// Optional variables fall back to documented defaults.
func Load() (*Config, error) {
	cfg := &Config{
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		RSAPrivateKeyPEM:  os.Getenv("IDP_RSA_PRIVATE_KEY"),
		RSAPrivateKeyPath: os.Getenv("IDP_RSA_PRIVATE_KEY_PATH"),
		Port:              getenvDefault("IDP_PORT", "8080"),
		JWTIssuer:         getenvDefault("IDP_JWT_ISSUER", "http://idp:8080"),
		JWTAudience:       getenvDefault("IDP_JWT_AUDIENCE", "zerotrust-api-gateway"),
	}

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("config: DATABASE_URL is not set — refusing to start without a database")
	}

	if cfg.RSAPrivateKeyPEM == "" && cfg.RSAPrivateKeyPath == "" {
		return nil, fmt.Errorf(
			"config: neither IDP_RSA_PRIVATE_KEY nor IDP_RSA_PRIVATE_KEY_PATH is set — " +
				"generate a key with `idp-server genkey` and add it to your .env",
		)
	}

	// Expand literal "\n" sequences. dotenv files cannot hold raw newlines in
	// a single quoted value, so PEM blocks are typically stored escaped.
	cfg.RSAPrivateKeyPEM = strings.ReplaceAll(cfg.RSAPrivateKeyPEM, `\n`, "\n")

	ttl, err := time.ParseDuration(getenvDefault("IDP_JWT_TTL", "15m"))
	if err != nil {
		return nil, fmt.Errorf("config: IDP_JWT_TTL is not a valid duration: %w", err)
	}
	cfg.JWTTTL = ttl

	return cfg, nil
}

func getenvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
