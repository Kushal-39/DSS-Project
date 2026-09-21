// Command shipper is the central audit logging consumer (Person 6).
//
// It follows the stdout of every container in this Compose project over the
// Docker API, tags each structured JSON line with the service that produced
// it, and forwards the result to the telemetry ingest API. Because it reads
// container stdout rather than instrumenting anything, a component becomes
// auditable simply by existing — no library, no per-service code, and no
// coupling between the audit pipeline and the services it watches.
//
// Container stdout that is not structured JSON is left to Loki (see the
// promtail configuration in observability/): the audit trail records security
// decisions, the log store records everything.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"telemetry/internal/collector"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel()}))
	slog.SetDefault(logger)

	if len(os.Args) > 1 && (os.Args[1] == "help" || os.Args[1] == "-h" || os.Args[1] == "--help") {
		fmt.Fprint(os.Stderr, `shipper — forwards container logs into the telemetry audit pipeline

Usage:
  shipper              Follow every container in this Compose project.

Environment (see .env.example):
  DOCKER_SOCKET                    Docker socket (default /var/run/docker.sock)
  TELEMETRY_URL                    telemetry ingest base URL (default http://telemetry:8088)
  TELEMETRY_INGEST_TOKEN           required: authenticates the collector
  TELEMETRY_SHIP_LABEL             container label selecting containers
  TELEMETRY_SHIP_PROJECT           label value to match (default: this project)
  TELEMETRY_SHIP_CONTAINERS        explicit allowlist of container names
  TELEMETRY_SHIP_SERVICE_PREFIX    prefix stripped from container names
  TELEMETRY_SHIP_ADDR              status listener (default :8089, empty to disable)
  TELEMETRY_SHIP_BACKFILL          first-read history (default 30m, "0s" for all)
`)
		return
	}

	cfg, err := collector.LoadShipperConfig()
	if err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	shipper := collector.NewShipper(cfg, logger)

	// The status listener runs alongside collection and is deliberately not
	// fatal: losing a metrics port must never stop the audit trail.
	statusErr := make(chan error, 1)
	go func() { statusErr <- shipper.ServeStatus(ctx) }()

	runErr := shipper.Run(ctx)
	if err := <-statusErr; err != nil {
		logger.Warn("collector_status_unavailable", "error", err)
	}
	if runErr != nil {
		logger.Error("fatal", "error", runErr)
		os.Exit(1)
	}
}

func logLevel() slog.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TELEMETRY_LOG_LEVEL"))) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
