package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

// setBase provides the minimum a valid non-TLS configuration needs, so each test
// only has to state the variable it is actually about.
func setBase(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/zerotrust")
	t.Setenv("PAYMENT_TLS_CERT_FILE", "/certs/payment-service.crt")
	t.Setenv("PAYMENT_TLS_KEY_FILE", "/certs/payment-service.key")
	t.Setenv("PAYMENT_TLS_CA_FILE", "/certs/ca.crt")
}

func TestLoadAppliesDocumentedDefaults(t *testing.T) {
	setBase(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Addr != ":8081" {
		t.Errorf("Addr = %q, want :8081", cfg.Addr)
	}
	if cfg.Store != StorePostgres {
		t.Errorf("Store = %q, want postgres", cfg.Store)
	}
	// Strict mTLS is the default: Person 5's deliverable is enforcing it.
	if !cfg.ServerTLS.RequireClientCert {
		t.Error("RequireClientCert must default to true")
	}
	if !cfg.EnforceSenderBinding {
		t.Error("EnforceSenderBinding must default to true")
	}
	if cfg.AllowInsecureHTTP || cfg.AllowInsecureUpstream {
		t.Error("insecure modes must be off by default")
	}
	if got := strings.Join(cfg.AllowedClientIDs, ","); got != "gateway,account-service" {
		t.Errorf("AllowedClientIDs = %q", got)
	}
	if cfg.PolicyURL != DefaultPolicyURL || cfg.JWKSURL != DefaultJWKSPath {
		t.Errorf("contract endpoint defaults are wrong: policy=%q jwks=%q", cfg.PolicyURL, cfg.JWKSURL)
	}
	if cfg.MaxTransfer.String() != DefaultMaxTransfer {
		t.Errorf("MaxTransfer = %q, want %q", cfg.MaxTransfer.String(), DefaultMaxTransfer)
	}
	if cfg.RequiresOTLPAuth() {
		t.Error("an empty OTLP token must not require authentication")
	}
	if len(cfg.WarnInsecure()) != 0 {
		t.Errorf("a strict configuration must produce no warnings, got %v", cfg.WarnInsecure())
	}
}

func TestLoadRefusesToServeWithoutTransportSecurity(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/zerotrust")

	_, err := Load()
	if err == nil {
		t.Fatal("a payment service must not start without TLS material")
	}
	if !strings.Contains(err.Error(), "PAYMENT_TLS_CERT_FILE") {
		t.Errorf("the error must name the variable that fixes it, got: %v", err)
	}
}

func TestLoadRefusesToMoveMoneyOverCleartextUpstream(t *testing.T) {
	setBase(t)
	t.Setenv("PAYMENT_ACCOUNT_SERVICE_URL", "http://account-service:8082")

	if _, err := Load(); err == nil {
		t.Fatal("an http:// Account Service URL must be refused by default")
	}

	t.Setenv("PAYMENT_ALLOW_INSECURE_UPSTREAM", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	warnings := strings.Join(cfg.WarnInsecure(), "\n")
	if !strings.Contains(warnings, "PAYMENT_ALLOW_INSECURE_UPSTREAM") {
		t.Errorf("startup must warn about the insecure upstream, got: %q", warnings)
	}
}

func TestLoadRequiresTheCAWhenClientCertificatesAreMandatory(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/zerotrust")
	t.Setenv("PAYMENT_TLS_CERT_FILE", "/certs/payment-service.crt")
	t.Setenv("PAYMENT_TLS_KEY_FILE", "/certs/payment-service.key")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "PAYMENT_TLS_CA_FILE") {
		t.Fatalf("requiring a client certificate without a CA must fail, got: %v", err)
	}
}

func TestLoadRequiresCertificateAndKeyTogether(t *testing.T) {
	setBase(t)
	t.Setenv("PAYMENT_TLS_KEY_FILE", "")

	if _, err := Load(); err == nil {
		t.Fatal("a certificate without its key must be refused")
	}
}

func TestLoadMemoryStoreNeedsNoDatabase(t *testing.T) {
	_ = setBase // its DATABASE_URL is cleared below; TLS material still applies.
	t.Setenv("DATABASE_URL", "")
	t.Setenv("PAYMENT_TLS_CERT_FILE", "/certs/payment-service.crt")
	t.Setenv("PAYMENT_TLS_KEY_FILE", "/certs/payment-service.key")
	t.Setenv("PAYMENT_TLS_CA_FILE", "/certs/ca.crt")
	t.Setenv("PAYMENT_STORE", "memory")

	if _, err := Load(); err != nil {
		t.Fatalf("the volatile store must work without DATABASE_URL: %v", err)
	}

	t.Setenv("PAYMENT_STORE", "postgres")
	if _, err := Load(); err == nil {
		t.Fatal("the durable store must refuse to start without DATABASE_URL")
	}
}

func TestLoadTreatsAMalformedValueAsFatal(t *testing.T) {
	setBase(t)

	t.Setenv("PAYMENT_TLS_REQUIRE_CLIENT_CERT", "flase")
	if _, err := Load(); err == nil {
		t.Fatal("a typo in a security switch must abort startup, not fall back to the default")
	}

	t.Setenv("PAYMENT_TLS_REQUIRE_CLIENT_CERT", "true")
	t.Setenv("PAYMENT_POLICY_TIMEOUT", "2 seconds")
	if _, err := Load(); err == nil {
		t.Fatal("a malformed duration must abort startup")
	}

	t.Setenv("PAYMENT_POLICY_TIMEOUT", "2s")
	t.Setenv("PAYMENT_MAX_TRANSFER_AMOUNT", "50.001")
	if _, err := Load(); err == nil {
		t.Fatal("a max transfer with sub-cent precision must abort startup")
	}
}

func TestLoadReadsOverrides(t *testing.T) {
	setBase(t)
	t.Setenv("PAYMENT_STORE", "MEMORY")
	t.Setenv("PAYMENT_ADDR", ":9999")
	t.Setenv("PAYMENT_LOG_LEVEL", "debug")
	t.Setenv("PAYMENT_SHUTDOWN_GRACE", "3s")
	t.Setenv("PAYMENT_ALLOWED_CLIENT_IDS", " gateway , account-service ,")
	t.Setenv("PAYMENT_MAX_TRANSFER_AMOUNT", "1234.56")
	t.Setenv("PAYMENT_ENFORCE_SENDER_BINDING", "false")
	t.Setenv("PAYMENT_OTLP_ENDPOINT", "http://telemetry:8088/v1/traces")
	t.Setenv("PAYMENT_OTLP_TOKEN", "token")
	t.Setenv("DATABASE_URL", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Store != StoreMemory || cfg.Addr != ":9999" || cfg.LogLevel != slog.LevelDebug {
		t.Errorf("overrides not applied: %+v", cfg)
	}
	if cfg.ShutdownGrace != 3*time.Second {
		t.Errorf("ShutdownGrace = %v", cfg.ShutdownGrace)
	}
	if got := strings.Join(cfg.AllowedClientIDs, ","); got != "gateway,account-service" {
		t.Errorf("AllowedClientIDs = %q, want the list trimmed", got)
	}
	if cfg.MaxTransfer.String() != "1234.56" {
		t.Errorf("MaxTransfer = %q", cfg.MaxTransfer.String())
	}
	if !cfg.RequiresOTLPAuth() {
		t.Error("a configured OTLP token must be required")
	}
	warnings := strings.Join(cfg.WarnInsecure(), "\n")
	if !strings.Contains(warnings, "PAYMENT_ENFORCE_SENDER_BINDING") {
		t.Errorf("disabling the sender binding must be warned about, got: %q", warnings)
	}
}

func TestLogValueRedactsSecrets(t *testing.T) {
	setBase(t)
	t.Setenv("DATABASE_URL", "postgres://user:supersecret@localhost:5432/zerotrust")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rendered := cfg.LogValue().String()
	// A startup banner is copied verbatim into the audit store's `raw` column
	// (telemetry/docs/integration.md §2), so it must not contain a credential.
	if strings.Contains(rendered, "supersecret") {
		t.Errorf("the configuration log leaks the database credential: %s", rendered)
	}
}
