package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

// The collector's own health and counters.
//
// An observability component that cannot be observed is the joke everyone makes
// about telemetry, so the collector answers the same questions the platform asks
// of every other service: is it alive, is it actually able to do its job, and
// what has it done so far. Readiness is meaningful rather than decorative — it
// reports whether the Docker API is reachable, because a collector that cannot
// see containers is running but useless, and "healthy but silently collecting
// nothing" is the failure mode that matters here.

// ServeStatus runs the collector's status server until ctx is cancelled.
//
// A failure to bind is returned but is not fatal to the collector: the audit
// path must not stop because a metrics port is already in use.
func (s *Shipper) ServeStatus(ctx context.Context) error {
	if s.cfg.StatusAddr == "" {
		return nil
	}
	listener, err := net.Listen("tcp", s.cfg.StatusAddr)
	if err != nil {
		return fmt.Errorf("collector: cannot listen on %s: %w", s.cfg.StatusAddr, err)
	}
	return s.serveStatus(ctx, listener)
}

// serveStatus runs the status server on an already-bound listener, so the
// address is known before the first request arrives.
func (s *Shipper) serveStatus(ctx context.Context, listener net.Listener) error {
	server := &http.Server{
		Handler:           s.statusHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       time.Minute,
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("collector_status_listening", "addr", listener.Addr().String())
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("collector: status server failed: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdown)
}

// statusHandler is the collector's own HTTP surface.
func (s *Shipper) statusHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "telemetry-collector"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ready, detail := s.readiness()
		status := http.StatusOK
		if !ready {
			status = http.StatusServiceUnavailable
		}
		writeStatusJSON(w, status, map[string]any{
			"status":     map[bool]string{true: "ready", false: "not_ready"}[ready],
			"service":    "telemetry-collector",
			"detail":     detail,
			"containers": s.followed.Load(),
			"shipped":    s.sent.Load(),
			"dropped":    s.dropped.Load(),
			"failed":     s.failed.Load(),
			"skipped":    s.skipped.Load(),
		})
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s.writeMetrics(w)
	})
	return mux
}

// readiness reports whether the collector can currently see containers.
func (s *Shipper) readiness() (bool, string) {
	last := s.lastDiscovery.Load()
	if last == 0 {
		return false, "no container discovery has succeeded yet"
	}
	age := time.Since(time.Unix(0, last))
	if age > 3*s.cfg.DiscoverInterval {
		return false, fmt.Sprintf("the Docker API has been unreachable for %s", age.Round(time.Second))
	}
	return true, fmt.Sprintf("following %d containers", s.followed.Load())
}

func (s *Shipper) writeMetrics(w http.ResponseWriter) {
	ready, detail := s.readiness()

	fmt.Fprintf(w, "# HELP telemetry_collector_containers_followed Containers whose logs are being followed.\n")
	fmt.Fprintf(w, "# TYPE telemetry_collector_containers_followed gauge\n")
	fmt.Fprintf(w, "telemetry_collector_containers_followed %d\n", s.followed.Load())

	fmt.Fprintf(w, "# HELP telemetry_collector_records_shipped_total Records accepted by the audit ingest API.\n")
	fmt.Fprintf(w, "# TYPE telemetry_collector_records_shipped_total counter\n")
	fmt.Fprintf(w, "telemetry_collector_records_shipped_total %d\n", s.sent.Load())

	fmt.Fprintf(w, "# HELP telemetry_collector_records_dropped_total Records shed because the ingest API could not keep up.\n")
	fmt.Fprintf(w, "# TYPE telemetry_collector_records_dropped_total counter\n")
	fmt.Fprintf(w, "telemetry_collector_records_dropped_total %d\n", s.dropped.Load())

	fmt.Fprintf(w, "# HELP telemetry_collector_batches_failed_total Batches abandoned after retries.\n")
	fmt.Fprintf(w, "# TYPE telemetry_collector_batches_failed_total counter\n")
	fmt.Fprintf(w, "telemetry_collector_batches_failed_total %d\n", s.failed.Load())

	fmt.Fprintf(w, "# HELP telemetry_collector_records_skipped_total Lines that were not structured JSON records.\n")
	fmt.Fprintf(w, "# TYPE telemetry_collector_records_skipped_total counter\n")
	fmt.Fprintf(w, "telemetry_collector_records_skipped_total %d\n", s.skipped.Load())

	fmt.Fprintf(w, "# HELP telemetry_collector_last_ingest_seconds_ago Seconds since the last accepted batch (-1 if none yet).\n")
	fmt.Fprintf(w, "# TYPE telemetry_collector_last_ingest_seconds_ago gauge\n")
	ago := float64(-1)
	if last := s.lastIngest.Load(); last > 0 {
		ago = time.Since(time.Unix(0, last)).Seconds()
	}
	fmt.Fprintf(w, "telemetry_collector_last_ingest_seconds_ago %s\n", strconv.FormatFloat(ago, 'f', 3, 64))

	fmt.Fprintf(w, "# HELP telemetry_collector_ready Whether the collector can see containers right now.\n")
	fmt.Fprintf(w, "# TYPE telemetry_collector_ready gauge\n")
	readyValue := 0
	if ready {
		readyValue = 1
	}
	fmt.Fprintf(w, "telemetry_collector_ready %d\n", readyValue)
	fmt.Fprintf(w, "# collector detail: %s\n", detail)
}

func writeStatusJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
