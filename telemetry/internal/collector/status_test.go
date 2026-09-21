package collector

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testShipper(cfg *ShipperConfig) *Shipper {
	if cfg == nil {
		cfg = &ShipperConfig{DiscoverInterval: 15 * time.Second, StatusAddr: ":8089"}
	}
	return &Shipper{
		cfg:          cfg,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		http:         &http.Client{Timeout: time.Second},
		retryBackoff: time.Millisecond,
		queue:        make(chan record, 16),
	}
}

// Readiness has to mean something: a collector that cannot see the Docker API
// is running, healthy and collecting nothing, which is the failure that would
// otherwise go unnoticed until someone asks why the dashboard is empty.
func TestReadinessTracksContainerDiscovery(t *testing.T) {
	shipper := testShipper(nil)
	handler := shipper.statusHandler()

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Errorf("before any discovery: status = %d, want 503", response.Code)
	}

	shipper.lastDiscovery.Store(time.Now().UnixNano())
	shipper.followed.Store(6)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusOK {
		t.Errorf("after discovery: status = %d, want 200", response.Code)
	}
	var payload struct {
		Status     string `json:"status"`
		Containers int64  `json:"containers"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Status != "ready" || payload.Containers != 6 {
		t.Errorf("payload = %+v, want ready with 6 containers", payload)
	}

	// A daemon that has been unreachable for several discovery cycles is not
	// ready, even though the process is up.
	shipper.lastDiscovery.Store(time.Now().Add(-time.Hour).UnixNano())
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Errorf("stale discovery: status = %d, want 503", response.Code)
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusOK {
		t.Errorf("liveness = %d, want 200 (the process is alive even when it cannot see containers)", response.Code)
	}
}

func TestMetricsExposeTheCollectorsCounters(t *testing.T) {
	shipper := testShipper(nil)
	shipper.lastDiscovery.Store(time.Now().UnixNano())
	shipper.followed.Store(8)
	shipper.queued.Add(128)
	shipper.sent.Add(120)
	shipper.dropped.Add(3)
	shipper.failed.Add(4)
	shipper.skipped.Add(99)
	shipper.lastIngest.Store(time.Now().Add(-2 * time.Second).UnixNano())

	response := httptest.NewRecorder()
	shipper.statusHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := response.Body.String()
	if contentType := response.Header().Get("Content-Type"); !strings.Contains(contentType, "text/plain; version=0.0.4") {
		t.Errorf("content type = %q, want the Prometheus text format", contentType)
	}
	for _, want := range []string{
		"telemetry_collector_containers_followed 8",
		"telemetry_collector_records_queued_total 128",
		"telemetry_collector_records_shipped_total 120",
		"telemetry_collector_records_dropped_total 3",
		"telemetry_collector_batches_failed_total 4",
		"telemetry_collector_records_skipped_total 99",
		"telemetry_collector_ready 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics are missing %q\n%s", want, body)
		}
	}
	if strings.Contains(body, "telemetry_collector_last_ingest_seconds_ago -1") {
		t.Error("last_ingest should report a real age once a batch has been accepted")
	}

	// queued > shipped means records are read but not delivered. That gap is the
	// only way to tell "nothing is happening" from "the ingest API is refusing
	// everything", which is why it is reported next to the other counters.
	if !strings.Contains(body, "telemetry_collector_records_queued_total 128") {
		t.Errorf("queued is not reported, so a delivery stall cannot be seen:\n%s", body)
	}
}

// A successful enqueue and a shed record must be counted differently: one is
// input accepted, the other is audit data lost, and a single counter for both
// would make a queue overflow look like normal traffic.
func TestEnqueueCountsAcceptedRecordsSeparatelyFromShedOnes(t *testing.T) {
	shipper := testShipper(nil)
	shipper.queue = make(chan record, 1)

	shipper.enqueue("idp", []byte(`{"msg":"http_request","status":200}`))
	shipper.enqueue("idp", []byte(`{"msg":"http_request","status":401}`))
	shipper.enqueue("idp", []byte("not json at all"))

	if got := shipper.queued.Load(); got != 1 {
		t.Errorf("queued = %d, want only the record that entered the pipeline", got)
	}
	if got := shipper.dropped.Load(); got != 1 {
		t.Errorf("dropped = %d, want the shed record", got)
	}
	if got := shipper.skipped.Load(); got != 1 {
		t.Errorf("skipped = %d, want the unstructured line", got)
	}
}

// Never having ingested anything is a state worth reporting, not a zero that
// looks like "just now".
func TestMetricsReportNoIngestYetAsNegative(t *testing.T) {
	response := httptest.NewRecorder()
	testShipper(nil).statusHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if !strings.Contains(response.Body.String(), "telemetry_collector_last_ingest_seconds_ago -1") {
		t.Errorf("want -1 for a collector that has not ingested yet:\n%s", response.Body.String())
	}
}

// The status server must come up on a real port and shut down with the
// collector, or a container restart leaves the port held.
func TestServeStatusBindsAndShutsDown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	shipper := testShipper(nil)
	shipper.lastDiscovery.Store(time.Now().UnixNano())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- shipper.serveStatus(ctx, listener) }()

	response, err := http.Get("http://" + listener.Addr().String() + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", response.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serveStatus returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveStatus did not return after cancellation")
	}
}

func TestStatusServerIsOptional(t *testing.T) {
	shipper := testShipper(&ShipperConfig{DiscoverInterval: time.Second})
	if err := shipper.ServeStatus(context.Background()); err != nil {
		t.Errorf("an empty status address must disable the listener, got %v", err)
	}
}

// --- configuration ---------------------------------------------------------

func TestShipperConfigDefaultsAndValidation(t *testing.T) {
	t.Setenv("TELEMETRY_INGEST_TOKEN", "token")

	cfg, err := LoadShipperConfig()
	if err != nil {
		t.Fatalf("LoadShipperConfig: %v", err)
	}
	if cfg.StatusAddr != ":8089" {
		t.Errorf("StatusAddr = %q, want :8089", cfg.StatusAddr)
	}
	if cfg.Backfill != 30*time.Minute {
		t.Errorf("Backfill = %s, want 30m", cfg.Backfill)
	}

	// An explicitly empty address turns the status server off, which is how a
	// deployment that already scrapes something else avoids a second port.
	t.Setenv("TELEMETRY_SHIP_ADDR", "")
	cfg, err = LoadShipperConfig()
	if err != nil {
		t.Fatalf("LoadShipperConfig: %v", err)
	}
	if cfg.StatusAddr != "" {
		t.Errorf("StatusAddr = %q, want it disabled", cfg.StatusAddr)
	}

	// Zero means "read everything the container still holds", so it has to be
	// expressible (Go durations need a unit) while a negative value does not.
	t.Setenv("TELEMETRY_SHIP_BACKFILL", "0s")
	cfg, err = LoadShipperConfig()
	if err != nil {
		t.Fatalf("LoadShipperConfig(backfill 0s): %v", err)
	}
	if cfg.Backfill != 0 {
		t.Errorf("Backfill = %s, want 0", cfg.Backfill)
	}

	// Go accepts a bare "0" as well as "0s", so only genuinely unparseable or
	// negative values are rejected.
	for _, bad := range []string{"-1s", "half an hour", "30"} {
		t.Setenv("TELEMETRY_SHIP_BACKFILL", bad)
		if _, err := LoadShipperConfig(); err == nil {
			t.Errorf("TELEMETRY_SHIP_BACKFILL=%q was accepted", bad)
		}
	}
}

// The collector cannot authenticate to the audit API without a token, and a
// collector that starts anyway would silently drop every record it reads.
func TestShipperConfigRequiresTheIngestToken(t *testing.T) {
	t.Setenv("TELEMETRY_INGEST_TOKEN", "")
	if _, err := LoadShipperConfig(); err == nil {
		t.Fatal("a missing ingest token was accepted")
	} else if !strings.Contains(err.Error(), "TELEMETRY_INGEST_TOKEN") {
		t.Errorf("error = %v, want it to name the variable", err)
	}
}
