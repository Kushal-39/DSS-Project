// Command server is the Identity Provider (IdP) binary.
//
// Subcommands (driven by the container entrypoint):
//
//	migrate   apply pending schema migrations against DATABASE_URL
//	seed      insert the bootstrap users (idempotent)
//	serve     start the HTTP API (runs after migrate + seed in the container)
//
// Developer utilities:
//
//	genkey    print a fresh RSA private key (PEM) for IDP_RSA_PRIVATE_KEY
//	hash      print the bcrypt hash of a password (for seeding)
//
// Configuration comes exclusively from environment variables injected via
// the git-crypt-encrypted .env; missing required variables abort startup.
package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"idp/internal/auth"
	"idp/internal/config"
	"idp/internal/db"
	"idp/internal/httpapi"
	"idp/internal/keys"
	"idp/migrations"
)

const usage = `idp-server — Zero-Trust Identity Provider

Usage:
  idp-server migrate          apply schema migrations (idempotent)
  idp-server seed             seed bootstrap users (idempotent)
  idp-server serve            start the HTTP API
  idp-server genkey           print a fresh RSA private key for .env
  idp-server hash <password>  print a bcrypt hash for seed data

Environment (required):
  DATABASE_URL               PostgreSQL connection string
  IDP_RSA_PRIVATE_KEY        RSA private key, PEM, "\n"-escaped
  IDP_RSA_PRIVATE_KEY_PATH   alternative: path to a PEM key file

Environment (optional):
  IDP_PORT                   HTTP listen port (default 8080)
  IDP_JWT_ISSUER             issuer claim (default http://idp:8080)
  IDP_JWT_AUDIENCE           audience claim (default zerotrust-api-gateway)
  IDP_JWT_TTL                token lifetime (default 15m)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	// Structured JSON logs for Person 6's pipeline (docs/flow.md §6).
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(logger)
	case "migrate":
		err = runMigrate(logger)
	case "seed":
		err = runSeed(logger)
	case "genkey":
		err = runGenKey()
	case "hash":
		if len(os.Args) < 3 {
			err = errors.New("hash: expected a password argument")
		} else {
			err = runHash(os.Args[2])
		}
	default:
		fmt.Fprintf(os.Stderr, "idp-server: unknown subcommand %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

// loadConfig fails fast: any missing required environment variable aborts
// with a descriptive error before any network or HTTP work begins.
func loadConfig() (*config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("configuration error: %w", err)
	}
	return cfg, nil
}

func runMigrate(logger *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	logger.Info("migrate: starting")

	// A short overall budget so a dead database URL fails fast instead of
	// hanging the container startup forever.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := db.Migrate(ctx, cfg.DatabaseURL, migrations.FS); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	logger.Info("migrate: complete")
	return nil
}

func runSeed(logger *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	logger.Info("seed: starting")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	defer pool.Close()

	seedSQL, err := migrations.FS.ReadFile("seed.sql")
	if err != nil {
		return fmt.Errorf("seed: failed to read embedded seed script: %w", err)
	}
	if err := db.Seed(ctx, pool, string(seedSQL)); err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	logger.Info("seed: complete")
	return nil
}

func runServe(logger *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// 1. Load the RSA signing key (fail fast on a bad/missing key).
	privateKey, err := loadSigningKey(cfg)
	if err != nil {
		return err
	}
	signKey, err := keys.New(privateKey)
	if err != nil {
		return fmt.Errorf("serve: failed to derive key identity: %w", err)
	}
	logger.Info("serve: signing key loaded", "kid", signKey.Kid)

	// 2. Connect to the database.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	defer pool.Close()

	// 3. Wire up the HTTP API.
	store := dbStore{pool: pool}
	issuer := &auth.Issuer{
		Key:      signKey.Private,
		Kid:      signKey.Kid,
		Issuer:   cfg.JWTIssuer,
		Audience: cfg.JWTAudience,
		TTL:      cfg.JWTTTL,
	}
	handler := httpapi.New(logger, store, issuer, signKey, pool)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		logger.Info("serve: listening", "addr", srv.Addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: http server failed: %w", err)
		}
	case sig := <-stop:
		logger.Info("serve: shutting down", "signal", sig.String())
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("serve: graceful shutdown failed: %w", err)
		}
	}
	logger.Info("serve: stopped")
	return nil
}

// dbStore adapts the pgx pool to the auth.Store interface.
type dbStore struct {
	pool *pgxpool.Pool
}

var _ auth.Store = (*dbStore)(nil)

func (s dbStore) GetUserByUsername(ctx context.Context, username string) (*auth.User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT user_id, username, password_hash, role
		   FROM credentials
		  WHERE username = $1`, username)

	var u auth.User
	if err := row.Scan(&u.UserID, &u.Username, &u.PasswordHash, &u.Role); err != nil {
		return nil, err
	}
	return &u, nil
}

func runGenKey() error {
	key, err := keys.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("genkey: %w", err)
	}
	fmt.Println(keys.PrivateKeyToPEM(key))
	return nil
}

func runHash(password string) error {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash: %w", err)
	}
	fmt.Println(string(h))
	return nil
}

// loadSigningKey resolves the RSA private key from the environment. The PEM
// string in IDP_RSA_PRIVATE_KEY takes precedence; IDP_RSA_PRIVATE_KEY_PATH
// is the fallback (e.g. Docker secrets). Any failure aborts startup — the
// IdP refuses to run without its signing identity.
func loadSigningKey(cfg *config.Config) (*rsa.PrivateKey, error) {
	pemData := cfg.RSAPrivateKeyPEM
	if pemData == "" {
		data, err := os.ReadFile(cfg.RSAPrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("serve: failed to read key file %q: %w", cfg.RSAPrivateKeyPath, err)
		}
		pemData = string(data)
	}

	key, err := keys.LoadPrivateKey(pemData)
	if err != nil {
		return nil, fmt.Errorf("serve: %w", err)
	}
	return key, nil
}
