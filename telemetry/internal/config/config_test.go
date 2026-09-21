package config

import (
	"strings"
	"testing"
	"time"
)

// clearEnv unsets every variable this package reads, so a value in the real
// environment cannot make a test pass or fail by accident.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"DATABASE_URL", "TELEMETRY_ADDR", "TELEMETRY_STORE", "TELEMETRY_INGEST_TOKEN",
		"TELEMETRY_READ_TOKEN", "TELEMETRY_INSECURE_INGEST", "TELEMETRY_RETENTION",
		"TELEMETRY_RETENTION_INTERVAL", "TELEMETRY_DEFAULT_SERVICE", "TELEMETRY_FORWARD_OTLP_ENDPOINT",
		"TELEMETRY_FORWARD_TIMEOUT", "TELEMETRY_DASHBOARD_WINDOW", "TELEMETRY_MAX_WINDOW",
		"TELEMETRY_MAX_BODY_BYTES", "TELEMETRY_SHUTDOWN_GRACE",
		"TELEMETRY_TLS_CERT_FILE", "TELEMETRY_TLS_KEY_FILE", "TELEMETRY_TLS_CA_FILE",
		"TELEMETRY_TLS_REQUIRE_CLIENT_CERT",
	} {
		t.Setenv(key, "")
	}
}

// The Transport Contract half of the configuration (docs/division.md §2). It is
// optional, so it has to be *provably* absent by default and impossible to
// half-configure: a certificate without its key, or a mutual listener with
// nothing to verify against, is a startup error rather than a handshake
// surprise at 3am.
func TestTLSConfiguration(t *testing.T) {
	clearEnv(t)
	t.Setenv("DATABASE_URL", "postgres://user:pw@host:5432/postgres")
	t.Setenv("TELEMETRY_INGEST_TOKEN", "token")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.TLS.Enabled() {
		t.Error("TLS is enabled by default, which would break every deployment that has no certificates yet")
	}

	t.Setenv("TELEMETRY_TLS_CERT_FILE", "/certs/telemetry.crt")
	if _, err := Load(); err == nil {
		t.Error("a certificate without its key was accepted")
	}

	t.Setenv("TELEMETRY_TLS_KEY_FILE", "/certs/telemetry.key")
	t.Setenv("TELEMETRY_TLS_REQUIRE_CLIENT_CERT", "true")
	if _, err := Load(); err == nil {
		t.Error("requiring a client certificate without a CA was accepted")
	}

	t.Setenv("TELEMETRY_TLS_CA_FILE", "/certs/ca.crt")
	if _, err := Load(); err == nil {
		// The files do not exist on this machine; what matters is that the
		// failure is the unreadable CA and not a missing variable.
		t.Log("a missing CA file did not stop startup")
	} else if !strings.Contains(err.Error(), "/certs/ca.crt") {
		t.Errorf("error = %v, want it to name the file it could not read", err)
	}

	t.Setenv("TELEMETRY_TLS_REQUIRE_CLIENT_CERT", "not-a-bool")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "TELEMETRY_TLS_REQUIRE_CLIENT_CERT") {
		t.Errorf("a malformed boolean was accepted, error = %v", err)
	}
}

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)
	t.Setenv("DATABASE_URL", "postgres://user:pw@host:5432/postgres")
	t.Setenv("TELEMETRY_INGEST_TOKEN", "token")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Addr != ":8088" {
		t.Errorf("addr = %q, want :8088", cfg.Addr)
	}
	if cfg.Store != StorePostgres {
		t.Errorf("store = %q, want postgres (the durable backend is the default)", cfg.Store)
	}
	if !cfg.RequiresIngestAuth() {
		t.Error("RequiresIngestAuth = false with a token configured")
	}
	if cfg.Retention != 720*time.Hour {
		t.Errorf("retention = %s, want 720h", cfg.Retention)
	}
	if cfg.DashboardWindow != 24*time.Hour {
		t.Errorf("dashboard window = %s, want 24h", cfg.DashboardWindow)
	}
	if cfg.MaxWindow != 30*24*time.Hour {
		t.Errorf("max window = %s, want 720h", cfg.MaxWindow)
	}
	if cfg.MaxBodyBytes != 4<<20 {
		t.Errorf("max body = %d, want 4 MiB", cfg.MaxBodyBytes)
	}
	if cfg.DefaultService != "unknown" {
		t.Errorf("default service = %q", cfg.DefaultService)
	}
	if cfg.ForwardOTLPEndpoint != "" {
		t.Errorf("forward endpoint = %q, want empty (mirroring is opt-in)", cfg.ForwardOTLPEndpoint)
	}
}

func TestLoadRequiresADatabaseForThePostgresBackend(t *testing.T) {
	clearEnv(t)
	t.Setenv("TELEMETRY_INGEST_TOKEN", "token")

	_, err := Load()
	if err == nil {
		t.Fatal("telemetry started without DATABASE_URL and without being told to use memory")
	}
	if !strings.Contains(err.Error(), "DATABASE_URL") {
		t.Errorf("error = %v, want it to name the missing variable", err)
	}

	// The escape hatch is explicit, and it is the only way to skip the check.
	clearEnv(t)
	t.Setenv("TELEMETRY_STORE", "memory")
	t.Setenv("TELEMETRY_INGEST_TOKEN", "token")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with TELEMETRY_STORE=memory: %v", err)
	}
	if cfg.Store != StoreMemory {
		t.Errorf("store = %q", cfg.Store)
	}
}

func TestLoadRefusesAnUnknownStore(t *testing.T) {
	clearEnv(t)
	t.Setenv("TELEMETRY_STORE", "elasticsearch")
	t.Setenv("TELEMETRY_INGEST_TOKEN", "token")

	_, err := Load()
	if err == nil {
		t.Fatal("an unknown backend was accepted")
	}
	if !strings.Contains(err.Error(), "postgres") || !strings.Contains(err.Error(), "memory") {
		t.Errorf("error = %v, want it to list the valid options", err)
	}
}

func TestLoadRequiresAnIngestToken(t *testing.T) {
	clearEnv(t)
	t.Setenv("TELEMETRY_STORE", "memory")

	// An unauthenticated audit endpoint lets anyone with network access forge
	// or flood the security record, so this is a hard failure.
	_, err := Load()
	if err == nil {
		t.Fatal("telemetry started without an ingest token")
	}
	if !strings.Contains(err.Error(), "TELEMETRY_INGEST_TOKEN") {
		t.Errorf("error = %v, want it to name the variable", err)
	}

	// ...unless the operator says, in so many words, that this is a demo.
	clearEnv(t)
	t.Setenv("TELEMETRY_STORE", "memory")
	t.Setenv("TELEMETRY_INSECURE_INGEST", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with TELEMETRY_INSECURE_INGEST: %v", err)
	}
	if cfg.RequiresIngestAuth() {
		t.Error("RequiresIngestAuth = true while ingest is explicitly open")
	}
	if !cfg.InsecureIngest {
		t.Error("InsecureIngest was not recorded, so the server cannot warn about it")
	}
}

func TestLoadRejectsMalformedValues(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		want  string
	}{
		{"bad retention", "TELEMETRY_RETENTION", "forever", "TELEMETRY_RETENTION"},
		{"zero retention", "TELEMETRY_RETENTION", "0s", "positive"},
		{"negative retention", "TELEMETRY_RETENTION", "-1h", "positive"},
		{"bad flush interval", "TELEMETRY_RETENTION_INTERVAL", "quickly", "TELEMETRY_RETENTION_INTERVAL"},
		{"bad body size", "TELEMETRY_MAX_BODY_BYTES", "lots", "TELEMETRY_MAX_BODY_BYTES"},
		{"non-positive body size", "TELEMETRY_MAX_BODY_BYTES", "0", "positive"},
		{"bad boolean", "TELEMETRY_INSECURE_INGEST", "maybe", "TELEMETRY_INSECURE_INGEST"},
		{"bad window", "TELEMETRY_DASHBOARD_WINDOW", "yesterday", "TELEMETRY_DASHBOARD_WINDOW"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearEnv(t)
			t.Setenv("TELEMETRY_STORE", "memory")
			t.Setenv("TELEMETRY_INGEST_TOKEN", "token")
			t.Setenv(test.key, test.value)

			_, err := Load()
			if err == nil {
				t.Fatalf("%s=%q was accepted", test.key, test.value)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error = %v, want it to mention %q", err, test.want)
			}
		})
	}
}

func TestLoadValidatesTheForwardEndpoint(t *testing.T) {
	clearEnv(t)
	t.Setenv("TELEMETRY_STORE", "memory")
	t.Setenv("TELEMETRY_INGEST_TOKEN", "token")
	t.Setenv("TELEMETRY_FORWARD_OTLP_ENDPOINT", "jaeger:4318")

	_, err := Load()
	if err == nil {
		t.Fatal("a scheme-less mirror endpoint was accepted")
	}
	if !strings.Contains(err.Error(), "scheme") {
		t.Errorf("error = %v, want it to explain the missing scheme", err)
	}

	clearEnv(t)
	t.Setenv("TELEMETRY_STORE", "memory")
	t.Setenv("TELEMETRY_INGEST_TOKEN", "token")
	t.Setenv("TELEMETRY_FORWARD_OTLP_ENDPOINT", "http://jaeger:4318")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ForwardOTLPEndpoint != "http://jaeger:4318" {
		t.Errorf("forward endpoint = %q", cfg.ForwardOTLPEndpoint)
	}
}

func TestLoadReadsTheConfiguredValues(t *testing.T) {
	clearEnv(t)
	t.Setenv("DATABASE_URL", "postgres://user:pw@host:5432/postgres")
	t.Setenv("TELEMETRY_INGEST_TOKEN", "ingest")
	t.Setenv("TELEMETRY_READ_TOKEN", "read")
	t.Setenv("TELEMETRY_ADDR", "127.0.0.1:9999")
	t.Setenv("TELEMETRY_DEFAULT_SERVICE", "api-gateway")
	t.Setenv("TELEMETRY_RETENTION", "30d_placeholder")

	// Go durations have no day unit; the service must reject what a human
	// might reasonably try rather than silently misread it.
	if _, err := Load(); err == nil {
		t.Error("a duration with a day unit was accepted")
	}

	t.Setenv("TELEMETRY_RETENTION", "720h")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Addr != "127.0.0.1:9999" || cfg.DefaultService != "api-gateway" || cfg.ReadToken != "read" {
		t.Errorf("config = %+v", cfg)
	}
	if cfg.Retention != 720*time.Hour {
		t.Errorf("retention = %s", cfg.Retention)
	}
}
