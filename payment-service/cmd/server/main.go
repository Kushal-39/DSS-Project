// Command server is the Payment & Transaction Service binary (Person 5).
//
// Subcommands:
//
//	serve                 run the mTLS API (the container's main process)
//	migrate up            apply the ledger migrations (idempotent)
//	migrate down --yes    roll the ledger migrations back (destructive)
//	migrate status        report the applied schema version
//	certs                 mint a local development CA and the mTLS certificates
//	healthcheck           probe /healthz over mTLS (used by the image's health
//	                      check, because a mutually-authenticated endpoint
//	                      cannot be probed by a bare `wget`)
//	help                  show this message
//
// Configuration comes exclusively from environment variables injected via the
// git-crypt-encrypted .env; a missing or malformed required variable aborts
// startup with a message that says how to fix it (see internal/config).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"paymentservice/internal/account"
	"paymentservice/internal/audit"
	"paymentservice/internal/certgen"
	"paymentservice/internal/config"
	"paymentservice/internal/db"
	"paymentservice/internal/httpapi"
	"paymentservice/internal/jwtauth"
	"paymentservice/internal/metrics"
	"paymentservice/internal/mtls"
	"paymentservice/internal/payments"
	"paymentservice/internal/policy"
	"paymentservice/internal/store"
	"paymentservice/internal/tracing"

	"paymentservice/migrations"
)

const usage = `payment-server — Zero-Trust Payment & Transaction Service (Person 5)

Usage:
  payment-server serve                              run the mTLS API
  payment-server migrate up|down|status [--yes]      manage the ledger schema
  payment-server certs [--dir ./certs] [--force]     mint a local development CA
  payment-server healthcheck [--url …] [--ca …]      probe /healthz over mTLS
  payment-server help                                show this message

Environment (required):
  DATABASE_URL                       the ledger database (unless PAYMENT_STORE=memory)
  PAYMENT_TLS_CERT_FILE              this service's certificate (server auth)
  PAYMENT_TLS_KEY_FILE               the matching private key
  PAYMENT_TLS_CA_FILE                the shared CA that signed the callers'

Environment (see .env.example for the full list):
  PAYMENT_ADDR                       listen address (default :8081)
  PAYMENT_STORE                      postgres | memory (default postgres)
  PAYMENT_JWKS_URL                   the IdP's key set
  PAYMENT_POLICY_URL                 the OPA decision endpoint
  PAYMENT_ACCOUNT_SERVICE_URL        Person 4's Account Service
  PAYMENT_UPSTREAM_TLS_*             this service's client identity for that call
  PAYMENT_ALLOWED_CLIENT_IDS         identities allowed to call the API
  PAYMENT_OTLP_ENDPOINT              Person 6's span receiver
`

// serviceShutdownGrace bounds how long in-flight requests get on SIGTERM when
// the configuration does not say.
const serviceShutdownGrace = 15 * time.Second

func main() {
	// A logger is available before the configuration is loaded, so a
	// configuration failure is itself reported as a structured line.
	logger := newLogger(slog.LevelInfo)
	slog.SetDefault(logger)

	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(logger)
	case "migrate":
		err = runMigrate(logger, os.Args[2:])
	case "certs":
		err = runCerts(logger, os.Args[2:])
	case "healthcheck":
		err = runHealthcheck(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Fprint(os.Stdout, usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "payment-server: unknown subcommand %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

// newLogger builds the structured JSON logger Person 6's pipeline reads.
//
// The one non-obvious part is the UTC rewrite: log/slog stamps `time` in the
// process's local zone, and telemetry's ingest classifies a record dated in the
// future as stored-but-invisible (telemetry/docs/integration.md §2 "Always log
// time — in UTC"). Normalising here means a container running with a local TZ
// still produces a trail that the dashboard's windows include.
func newLogger(level slog.Level) *slog.Logger {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, attribute slog.Attr) slog.Attr {
			if len(groups) == 0 && attribute.Key == slog.TimeKey {
				if stamp, ok := attribute.Value.Any().(time.Time); ok {
					return slog.Time(slog.TimeKey, stamp.UTC())
				}
			}
			return attribute
		},
	})
	return slog.New(handler)
}

func loadConfig() (*config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("configuration error: %w", err)
	}
	return cfg, nil
}

func runServe(baseLogger *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// The configured level only exists once the environment is parsed, so the
	// real logger is created here and becomes the default for every package.
	logger := newLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	logger.Info("starting", "config", cfg.LogValue())
	for _, warning := range cfg.WarnInsecure() {
		logger.Warn("insecure_configuration", "warning", warning,
			"note", "this is acceptable for local development and never for a shared environment")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// ---- ledger ----------------------------------------------------------

	ledger, err := store.Open(ctx, cfg)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	defer ledger.Close()

	// ---- collaborators ---------------------------------------------------

	jwksClient, err := httpClientFor(cfg.JWKSRequestTimeout, cfg.JWKSRequestTLS)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	verifier, err := jwtauth.New(jwtauth.Options{
		JWKSURL:     cfg.JWKSURL,
		Issuer:      cfg.JWTIssuer,
		Audience:    cfg.JWTAudience,
		ClockSkew:   cfg.JWTClockSkew,
		CacheTTL:    cfg.JWKSRefreshInterval,
		KidThrottle: cfg.JWKSUnknownKidInterval,
		HTTPClient:  jwksClient,
	})
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	policyTLS, err := tlsConfigFor(cfg.PolicyTLS)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	policyClient, err := policy.New(policy.Options{
		URL:     cfg.PolicyURL,
		Timeout: cfg.PolicyTimeout,
		TLS:     policyTLS,
	})
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	accountTLS, err := tlsConfigFor(cfg.AccountServiceTLS)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	accountClient, err := account.New(account.Options{
		BaseURL:       cfg.AccountServiceURL,
		Timeout:       cfg.AccountServiceTimeout,
		TLS:           accountTLS,
		AllowInsecure: cfg.AllowInsecureUpstream,
	})
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	registry := metrics.New()
	registry.Describe(metrics.RequestsTotal, "HTTP requests by route, method and status class.")
	registry.Describe(metrics.MTLSRejectionsTotal, "TLS handshakes refused, by reason.")
	registry.Describe(metrics.PolicyDecisionsTotal, "Policy engine verdicts returned to this service.")
	registry.Describe(metrics.TransfersTotal, "Transfer outcomes.")
	registry.Describe(metrics.UpstreamFailuresTotal, "Failed calls to a dependency.")
	registry.Describe(metrics.LedgerWritesTotal, "Ledger rows written.")
	registry.Describe(metrics.SpanExportFailuresTotal, "Spans dropped or refused by the span exporter.")

	otlpTLS, err := tlsConfigFor(cfg.OTLPRequestTLS)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	tracer := tracing.New(tracing.Options{
		Endpoint:    cfg.OTLPEndpoint,
		Token:       cfg.OTLPToken,
		ServiceName: cfg.ServiceName,
		Timeout:     cfg.OTLPTimeout,
		TLS:         otlpTLS,
		Logger:      logger,
		Metrics:     registry,
	})
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tracer.Shutdown(shutdownCtx); err != nil {
			logger.Warn("span_exporter_shutdown", "error", err)
		}
	}()
	if !tracer.Enabled() {
		logger.Info("span_export_disabled", "note", "PAYMENT_OTLP_ENDPOINT is empty; audit decisions still reach the pipeline over stdout")
	}

	recorder := audit.New(logger, cfg.ServiceName)

	transferService := payments.New(payments.Options{
		Config:   cfg,
		Store:    ledger,
		Policy:   policyClient,
		Accounts: accountClient,
		Audit:    recorder,
		Metrics:  registry,
		Tracer:   tracer,
		Logger:   logger,
	})

	handler := httpapi.New(httpapi.Deps{
		Config:   cfg,
		Logger:   logger,
		Verifier: verifier,
		Payments: transferService,
		Store:    ledger,
		Audit:    recorder,
		Metrics:  registry,
		Tracer:   tracer,
	})

	server := &http.Server{
		Addr:    cfg.Addr,
		Handler: handler,
		// Bounded everywhere: an internal financial endpoint should not be the
		// place a slow client parks a connection.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// ---- listener --------------------------------------------------------

	var listener net.Listener
	insecure := false
	if cfg.ServerTLS.Enabled() {
		serverConfig, err := mtls.ServerSettings{
			CertFile:          cfg.ServerTLS.CertFile,
			KeyFile:           cfg.ServerTLS.KeyFile,
			CAFile:            cfg.ServerTLS.CAFile,
			RequireClientCert: cfg.ServerTLS.RequireClientCert,
		}.ServerConfig()
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		raw, err := net.Listen("tcp", cfg.Addr)
		if err != nil {
			return fmt.Errorf("serve: cannot listen on %s: %w", cfg.Addr, err)
		}
		// The handshake is performed inside the listener so a refused peer is
		// audited: a client without a certificate never reaches a handler, and
		// without this line it would leave no trace at all
		// (telemetry/docs/integration.md §3).
		listener = mtls.NewListener(raw, serverConfig, httpapi.HandshakeTimeout, func(rejection mtls.Rejection) {
			httpapi.RecordHandshakeRejection(recorder, registry, rejection)
		})
	} else {
		insecure = true
		raw, err := net.Listen("tcp", cfg.Addr)
		if err != nil {
			return fmt.Errorf("serve: cannot listen on %s: %w", cfg.Addr, err)
		}
		listener = raw
	}

	logger.Info("listening",
		"addr", cfg.Addr,
		"tls", !insecure,
		"require_client_cert", cfg.ServerTLS.RequireClientCert,
		"allowed_client_ids", cfg.AllowedClientIDs,
		"store", ledger.Kind(),
	)

	// ---- serve -----------------------------------------------------------

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: http server failed: %w", err)
		}
	case signalReceived := <-stop:
		logger.Info("shutting_down", "signal", signalReceived.String())
		grace := cfg.ShutdownGrace
		if grace <= 0 {
			grace = serviceShutdownGrace
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("serve: graceful shutdown failed: %w", err)
		}
	}
	logger.Info("stopped")
	return nil
}

// runMigrate applies, rolls back or reports the ledger schema.
//
// A rollback drops the ledger, so it needs an explicit --yes: an operator who
// mistypes a subcommand should not discover it from a missing ledger.
func runMigrate(logger *slog.Logger, args []string) error {
	flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
	confirm := flags.Bool("yes", false, "confirm a destructive rollback")
	action := "up"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action = args[0]
		args = args[1:]
	}
	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Store == config.StoreMemory {
		logger.Warn("migrate_skipped",
			"reason", "PAYMENT_STORE=memory uses an in-process ledger, so there is no schema to migrate",
			"note", "the volatile store is for local demos only")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	switch action {
	case "up":
		logger.Info("migrate: starting", "direction", "up")
		if err := db.Migrate(ctx, cfg.DatabaseURL, migrations.FS); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		logger.Info("migrate: complete", "direction", "up")
		return nil

	case "down":
		if !*confirm {
			return errors.New("migrate down: refusing to drop the ledger without --yes")
		}
		logger.Warn("migrate: starting", "direction", "down", "destructive", true)
		if err := db.MigrateDown(ctx, cfg.DatabaseURL, migrations.FS); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		logger.Info("migrate: complete", "direction", "down")
		return nil

	case "status":
		version, dirty, err := db.Version(cfg.DatabaseURL, migrations.FS)
		if err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		logger.Info("migrate: status", "version", version, "dirty", dirty)
		return nil

	default:
		return fmt.Errorf("migrate: unknown action %q (use up, down or status)", action)
	}
}

// runCerts mints the local development CA and the certificates the mTLS path
// needs. See internal/certgen for why this exists and what it does not do.
func runCerts(logger *slog.Logger, args []string) error {
	flags := flag.NewFlagSet("certs", flag.ContinueOnError)
	dir := flags.String("dir", "./certs", "directory to write the certificates into")
	hosts := flags.String("hosts", strings.Join(certgen.DefaultHosts, ","),
		"comma-separated DNS names for the server certificate")
	force := flags.Bool("force", false, "regenerate every file, even if the bundle is complete")
	if err := flags.Parse(args); err != nil {
		return err
	}

	created, err := certgen.WriteBundle(*dir, splitList(*hosts), *force)
	if err != nil {
		return err
	}
	if !created {
		logger.Info("certs: bundle already present",
			"dir", *dir,
			"note", "pass --force to regenerate (this invalidates every certificate already distributed)")
		return nil
	}

	logger.Warn("certs: development certificate authority created",
		"dir", *dir,
		"note", "these keys exist on disk and are for local development only; production certificates come "+
			"from the shared CA (docs/division.md §2)",
		"server_cert", certgen.ServerFile,
		"client_cert_for_account_service", certgen.ServerClientFile,
		"client_certs_for_peers", []string{certgen.AccountServiceFile, certgen.GatewayFile})
	return nil
}

// runHealthcheck probes /healthz over mTLS.
//
// The image needs this because the listener refuses a peer without a
// certificate: `wget` cannot present one, so the probe has to come from this
// binary. It writes nothing on success, so Docker's health status is driven by
// the exit code alone.
func runHealthcheck(args []string) error {
	flags := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := flags.String("url", "https://localhost:8081/healthz", "the health endpoint to probe")
	caFile := flags.String("ca", "", "CA that signed the server certificate")
	certFile := flags.String("cert", "", "client certificate to present")
	keyFile := flags.String("key", "", "client certificate key")
	serverName := flags.String("server-name", "", "name to verify in the server certificate")
	timeout := flags.Duration("timeout", 5*time.Second, "probe timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: *serverName}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			return fmt.Errorf("healthcheck: cannot read the CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("healthcheck: %s contains no PEM certificate", *caFile)
		}
		tlsConfig.RootCAs = pool
	}
	if *certFile != "" || *keyFile != "" {
		certificate, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			return fmt.Errorf("healthcheck: cannot load the client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	client := &http.Client{
		Timeout:   *timeout,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	response, err := client.Get(*url)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: %s returned %s", *url, response.Status)
	}
	return nil
}

// httpClientFor builds an HTTP client for an outbound dependency.
func httpClientFor(timeout time.Duration, settings config.ClientTLS) (*http.Client, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tlsConfig, err := tlsConfigFor(settings)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        8,
			IdleConnTimeout:     60 * time.Second,
			TLSHandshakeTimeout: 3 * time.Second,
			TLSClientConfig:     tlsConfig,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// A dependency that redirects is not something to follow with a
			// bearer token in hand.
			return http.ErrUseLastResponse
		},
	}, nil
}

// tlsConfigFor builds a client TLS configuration for an outbound dependency.
//
// An empty configuration returns nil, which means "use http.Transport's
// defaults": the plain-HTTP upstreams of this stack (the IdP's JWKS endpoint,
// the Policy Engine) are reached that way today.
//
// The verified server name is deliberately left to http.Transport: it sets
// ServerName from the request's URL host, which is exactly right for an
// internal address like https://account-service:8082, and it means this
// configuration cannot silently pin the wrong name. PAYMENT_*_TLS_SERVER_NAME
// exists for the case where the certificate and the address disagree.
func tlsConfigFor(settings config.ClientTLS) (*tls.Config, error) {
	if !settings.Enabled() {
		return nil, nil
	}
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: strings.TrimSpace(settings.ServerName),
	}
	if settings.CAFile != "" {
		pem, err := os.ReadFile(settings.CAFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read the CA file %q: %w", settings.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			// Failing here rather than trusting nothing: a CA file with no
			// certificate would reject every peer at handshake time, far from
			// the cause.
			return nil, fmt.Errorf("the CA file %q contains no PEM certificate", settings.CAFile)
		}
		config.RootCAs = pool
	}
	if settings.CertFile != "" {
		certificate, err := tls.LoadX509KeyPair(settings.CertFile, settings.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("cannot load the client certificate %q: %w", settings.CertFile, err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	return config, nil
}

func remoteHost(addr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return strings.TrimSpace(addr)
	}
	return host
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
