package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestClient points a Docker client at an httptest server. The real client
// dials a unix socket; overriding only the dialer exercises every line of the
// request building, framing and error handling for real.
func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	address := strings.TrimPrefix(server.URL, "http://")
	return &Client{
		socketPath: "test-socket",
		http: &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", address)
			},
		}},
	}
}

func TestListContainers(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/json" {
			t.Errorf("path = %q, want /containers/json", r.URL.Path)
		}
		if r.URL.Query().Get("all") != "0" {
			t.Errorf("all = %q, want 0 (running only)", r.URL.Query().Get("all"))
		}
		io.WriteString(w, `[
			{"Id":"aaaaaaaaaaaaaaaaaaaa","Names":["/dss-project-idp-1"],"Image":"dss-project-idp",
			 "Labels":{"com.docker.compose.project":"dss-project","com.docker.compose.service":"idp"}},
			{"Id":"bbbbbbbbbbbbbbbbbbbb","Names":["/unrelated"],"Image":"nginx","Labels":{}}
		]`)
	}))

	containers, err := client.ListContainers(context.Background())
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(containers) != 2 {
		t.Fatalf("got %d containers, want 2", len(containers))
	}
	if containers[0].Name != "dss-project-idp-1" {
		t.Errorf("name = %q, want the leading slash trimmed", containers[0].Name)
	}
	if containers[0].Labels["com.docker.compose.service"] != "idp" {
		t.Errorf("labels were lost: %v", containers[0].Labels)
	}
}

func TestClientReportsMissingAndFailingContainers(t *testing.T) {
	gone := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"No such container"}`, http.StatusNotFound)
	}))
	if _, err := gone.ListContainers(context.Background()); !errors.Is(err, ErrContainerGone) {
		t.Errorf("404 returned %v, want ErrContainerGone", err)
	}

	broken := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "daemon exploded", http.StatusInternalServerError)
	}))
	_, err := broken.ListContainers(context.Background())
	if err == nil {
		t.Fatal("a 500 from the daemon was reported as success")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %v, want the status in the message", err)
	}
	if strings.Contains(err.Error(), "daemon exploded") == false {
		t.Errorf("error = %v, want the daemon's message for diagnosis", err)
	}
}

func TestStreamLogsDemuxesTheFramedStream(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/json"):
			io.WriteString(w, `{"Config":{"Tty":false,"Labels":{"com.docker.compose.service":"idp"}}}`)
		case strings.HasSuffix(r.URL.Path, "/logs"):
			if r.URL.Query().Get("follow") != "1" {
				t.Errorf("follow = %q, want 1", r.URL.Query().Get("follow"))
			}
			if r.URL.Query().Get("since") != "1758440000" {
				t.Errorf("since = %q, want 1758440000", r.URL.Query().Get("since"))
			}
			// Two frames, each holding more than one line, plus a frame split
			// across a line boundary.
			w.Write(frame('1', `{"msg":"http_request","status":200}`+"\n"+`{"msg":"http_request","status":401}`+"\n"))
			w.Write(frame('1', `{"msg":"login_attempt","outcome":"denied"}`+"\n"))
			w.Write(frame('2', `{"msg":"http_panic","panic":"boom"}`+"\n"))
		}
	}))

	var lines []string
	err := client.StreamLogs(context.Background(), "aaaaaaaaaaaaaaaaaaaa",
		time.Unix(1758440000, 0), func(line []byte) {
			lines = append(lines, string(line))
		})
	if err != nil {
		t.Fatalf("StreamLogs: %v", err)
	}
	if len(lines) != 4 {
		t.Fatalf("got %d lines, want 4: %v", len(lines), lines)
	}
	if !strings.Contains(lines[1], "401") {
		t.Errorf("second line = %q, want the second record in the first frame", lines[1])
	}
	if !strings.Contains(lines[3], "http_panic") {
		t.Errorf("last line = %q, want the stderr frame's record", lines[3])
	}
}

func TestStreamLogsHandlesATtyContainer(t *testing.T) {
	// A TTY container's log stream is not multiplexed, so a demuxer would eat
	// its first nine bytes. The collector has to ask first.
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/json") {
			io.WriteString(w, `{"Config":{"Tty":true}}`)
			return
		}
		io.WriteString(w, `{"msg":"login_attempt","outcome":"permit"}`+"\n")
	}))

	var lines []string
	if err := client.StreamLogs(context.Background(), "id", time.Time{}, func(line []byte) {
		lines = append(lines, string(line))
	}); err != nil {
		t.Fatalf("StreamLogs: %v", err)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "login_attempt") {
		t.Fatalf("lines = %v, want the record intact", lines)
	}
}

func TestDemuxRejectsAnAbsurdFrame(t *testing.T) {
	header := make([]byte, 8)
	header[0] = 1
	binary.BigEndian.PutUint32(header[4:], 1<<30)

	err := demux(bytes.NewReader(header), func([]byte) error { return nil })
	if err == nil {
		t.Fatal("a 1 GiB frame header was accepted, so a malformed stream can exhaust memory")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error = %v", err)
	}
}

func TestDemuxStopsCleanlyAtEOF(t *testing.T) {
	// A truncated final frame ends the stream rather than erroring: the
	// container may have been killed mid-write.
	body := frame('1', "complete\n")
	body = append(body, 0x01, 0x00, 0x00) // half a header

	lines := 0
	if err := demux(bytes.NewReader(body), func(chunk []byte) error {
		lines += strings.Count(string(chunk), "\n")
		return nil
	}); err != nil {
		t.Fatalf("demux on a truncated stream: %v", err)
	}
	if lines != 1 {
		t.Errorf("got %d lines, want the one complete frame", lines)
	}
}

func TestEnrichLabelsTheServiceWithoutOverwritingTheProducer(t *testing.T) {
	// The IdP never names itself in a log line; the collector knows which
	// container the bytes came from, so it supplies the missing field.
	enriched, ok := enrich("idp", []byte(`{"msg":"http_request","status":401}`))
	if !ok {
		t.Fatal("a structured record was dropped")
	}
	var record map[string]any
	if err := json.Unmarshal(enriched, &record); err != nil {
		t.Fatalf("enrich produced invalid JSON: %v", err)
	}
	if record["service"] != "idp" {
		t.Errorf("service = %v, want idp", record["service"])
	}
	if record["status"] != float64(401) {
		t.Errorf("enrich lost the original fields: %v", record)
	}

	// A producer that does name itself wins: the collector must not overwrite
	// what the component said about itself.
	for _, key := range []string{"service", "component", "service_name", "app"} {
		enriched, ok := enrich("idp", []byte(`{"msg":"http_request","`+key+`":"api-gateway"}`))
		if !ok {
			t.Fatalf("record with %s was dropped", key)
		}
		if err := json.Unmarshal(enriched, &record); err != nil {
			t.Fatal(err)
		}
		if record["service"] != "api-gateway" {
			t.Errorf("with %s present, service = %v, want api-gateway", key, record["service"])
		}
	}

	// Unstructured output belongs to Loki, not to the audit trail.
	if _, ok := enrich("idp", []byte("Starting migration...")); ok {
		t.Error("a plain text line was accepted as an audit record")
	}
	if _, ok := enrich("idp", []byte("   ")); ok {
		t.Error("a blank line was accepted as an audit record")
	}
}

func TestServiceNameStripsTheComposeDecoration(t *testing.T) {
	shipper := &Shipper{cfg: &ShipperConfig{ServicePrefix: "dss-project-"}}
	tests := map[string]string{
		"dss-project-idp-1":                 "idp",
		"dss-project-telemetry-collector-1": "telemetry-collector",
		"dss-project-policy-engine-12":      "policy-engine",
		"dss-project-account-service-1":     "account-service",
		// Compose always appends -<replica index>, so it is stripped whatever
		// the prefix is; a name that only looks like an index keeps its tail.
		"another-project-idp-1": "another-project-idp",
		"dss-project-weird-1-2": "weird-1",
	}
	for container, want := range tests {
		if got := shipper.serviceName(container); got != want {
			t.Errorf("serviceName(%q) = %q, want %q", container, got, want)
		}
	}

	// Without a configured prefix the name is used as-is, minus the replica
	// index, because an unprefixed name is all the identity available.
	plain := &Shipper{cfg: &ShipperConfig{}}
	if got := plain.serviceName("idp-1"); got != "idp" {
		t.Errorf("serviceName(idp-1) = %q, want idp", got)
	}
	if got := plain.serviceName("-1"); got != "-1" {
		t.Errorf("serviceName(-1) = %q, want it left alone", got)
	}
}

func TestExcludeListDefaultsToThePipelineItself(t *testing.T) {
	// Shipping the telemetry service's own ingest log would feed the collector
	// the lines that generating more lines produced: a self-sustaining loop
	// that fills the audit trail with the observer.
	if got := excludeList(""); len(got) != 1 || got[0] != "telemetry" {
		t.Errorf("default exclude = %v, want [telemetry]", got)
	}
	if got := excludeList("-"); got != nil {
		t.Errorf("explicit '-' = %v, want nothing excluded", got)
	}
	if got := excludeList("telemetry, loki"); len(got) != 2 || got[1] != "loki" {
		t.Errorf("exclude = %v, want [telemetry loki]", got)
	}
}

func TestIsSelfMatchesTheShortContainerId(t *testing.T) {
	// Docker sets HOSTNAME to the short (12 character) container id while the
	// container list reports the full 64 character one. Comparing for equality
	// silently never matches, and a collector that follows itself loops.
	const shortID = "f44b2ff646e9"
	const fullID = "f44b2ff646e9aa5e4b3ff2f5a9f1f0f7d4a3c2b1a09e8d7c6b5a4938271605f"

	if !isSelf(Container{ID: fullID, Name: "dss-project-telemetry-collector-1"}, shortID, "") {
		t.Error("the collector did not recognise its own container by short id")
	}
	if !isSelf(Container{ID: "other", Name: "collector"}, "", "collector") {
		t.Error("the collector did not recognise itself by name")
	}
	other := "c3d4e5f6a7b8" + strings.Repeat("0", 52)
	if isSelf(Container{ID: other, Name: "dss-project-idp-1"}, shortID, "") {
		t.Error("an unrelated container was treated as self")
	}
	if isSelf(Container{ID: fullID, Name: "x"}, "", "") {
		t.Error("an empty identity matched every container")
	}
}

func TestSelectContainersAppliesLabelAllowlistAndExclusions(t *testing.T) {
	cfg := &ShipperConfig{
		LabelKey:      "com.docker.compose.project",
		LabelValue:    "dss-project",
		ServicePrefix: "dss-project-",
		Exclude:       []string{"telemetry"},
	}
	shipper := &Shipper{cfg: cfg}
	const selfID = "f44b2ff646e9"

	containers := []Container{
		{ID: "aaaa11112222", Name: "dss-project-idp-1", Labels: map[string]string{"com.docker.compose.project": "dss-project"}},
		{ID: "aaaa11113333", Name: "dss-project-telemetry-1", Labels: map[string]string{"com.docker.compose.project": "dss-project"}},
		{ID: selfID + "0000", Name: "dss-project-telemetry-collector-1", Labels: map[string]string{"com.docker.compose.project": "dss-project"}},
		{ID: "aaaa11114444", Name: "some-other-stack", Labels: map[string]string{"com.docker.compose.project": "other"}},
		{ID: "aaaa11115555", Name: "unlabelled", Labels: map[string]string{}},
	}

	selected := shipper.selectContainers(containers, selfID, "")
	if len(selected) != 1 || selected[0].Name != "dss-project-idp-1" {
		t.Fatalf("selected %+v, want only the idp container", selected)
	}

	// An explicit allowlist replaces label discovery.
	shipper.cfg.Containers = []string{"unlabelled"}
	selected = shipper.selectContainers(containers, selfID, "")
	if len(selected) != 1 || selected[0].Name != "unlabelled" {
		t.Fatalf("allowlist selected %+v", selected)
	}

	// Prefix matching supports short container ids, which is what a developer
	// has to hand. Four containers carry the prefix; the telemetry service is
	// still excluded, because an explicit allowlist does not override the
	// no-self-observation rule.
	shipper.cfg.Containers = []string{"aaaa1111"}
	selected = shipper.selectContainers(containers, selfID, "")
	if len(selected) != 3 {
		t.Fatalf("id prefix selected %d containers, want 3", len(selected))
	}
	for _, container := range selected {
		if shipper.excluded(container) {
			t.Errorf("%s should have been excluded", container.Name)
		}
	}
}

func TestLoadShipperConfigRequiresTheIngestToken(t *testing.T) {
	t.Setenv("TELEMETRY_INGEST_TOKEN", "")
	if _, err := LoadShipperConfig(); err == nil {
		t.Fatal("the collector started without an ingest token, so its batches " +
			"would be rejected one by one at runtime instead of failing fast")
	}

	t.Setenv("TELEMETRY_INGEST_TOKEN", "secret")
	t.Setenv("TELEMETRY_URL", "http://telemetry:8088/")
	t.Setenv("TELEMETRY_SHIP_FLUSH_INTERVAL", "3s")
	cfg, err := LoadShipperConfig()
	if err != nil {
		t.Fatalf("LoadShipperConfig: %v", err)
	}
	if cfg.Endpoint != "http://telemetry:8088" {
		t.Errorf("endpoint = %q, want the trailing slash trimmed", cfg.Endpoint)
	}
	if cfg.FlushInterval != 3*time.Second {
		t.Errorf("flush interval = %s, want 3s", cfg.FlushInterval)
	}
	if cfg.MaxBatch != 200 || cfg.QueueSize != 20000 {
		t.Errorf("defaults = batch %d queue %d, want 200/20000", cfg.MaxBatch, cfg.QueueSize)
	}

	t.Setenv("TELEMETRY_SHIP_FLUSH_INTERVAL", "not-a-duration")
	if _, err := LoadShipperConfig(); err == nil {
		t.Error("a malformed duration was accepted")
	}
	t.Setenv("TELEMETRY_SHIP_FLUSH_INTERVAL", "0s")
	if _, err := LoadShipperConfig(); err == nil {
		t.Error("a zero flush interval was accepted, which would spin")
	}
}

func TestPostSendsNDJSONWithTheCollectorToken(t *testing.T) {
	var gotPath, gotToken, gotContentType, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotToken, gotContentType = r.URL.Path, r.Header.Get("X-Telemetry-Token"), r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		io.WriteString(w, `{"accepted":2}`)
	}))
	defer server.Close()

	shipper := &Shipper{
		cfg:          &ShipperConfig{Endpoint: server.URL, Token: "collector-token"},
		http:         server.Client(),
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		retryBackoff: time.Millisecond,
	}

	shipper.post(context.Background(), []record{
		{service: "idp", line: []byte(`{"service":"idp","msg":"http_request"}`)},
		{service: "idp", line: []byte(`{"service":"idp","msg":"login_attempt"}`)},
	})

	if gotPath != "/v1/audit/logs" {
		t.Errorf("path = %q, want /v1/audit/logs", gotPath)
	}
	if gotToken != "collector-token" {
		t.Errorf("token = %q", gotToken)
	}
	if gotContentType != "application/x-ndjson" {
		t.Errorf("content-type = %q", gotContentType)
	}
	if lines := strings.Split(gotBody, "\n"); len(lines) != 2 {
		t.Errorf("body has %d lines, want 2: %q", len(lines), gotBody)
	}
	if got := shipper.sent.Load(); got != 2 {
		t.Errorf("sent = %d, want 2", got)
	}
}

func TestPostRetriesTransientFailuresAndGivesUpOnClientErrors(t *testing.T) {
	var attempts atomic.Int64
	shipper := &Shipper{
		cfg:          &ShipperConfig{Endpoint: "http://unused", Token: "t"},
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		retryBackoff: time.Millisecond,
	}

	// A 503 is the ingest API being busy; it is worth retrying.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) < 3 {
			http.Error(w, "starting up", http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, `{"accepted":1}`)
	}))
	shipper.cfg.Endpoint = server.URL
	shipper.http = server.Client()
	shipper.post(context.Background(), []record{{line: []byte(`{}`)}})
	if shipper.sent.Load() != 1 {
		t.Errorf("a transient failure was not retried (sent = %d, attempts = %d)",
			shipper.sent.Load(), attempts.Load())
	}
	server.Close()

	// A 400 is our fault and will not fix itself, so it must not be retried
	// five times.
	attempts.Store(0)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, `{"error":"invalid_payload"}`, http.StatusBadRequest)
	}))
	defer bad.Close()
	shipper.cfg.Endpoint = bad.URL
	shipper.http = bad.Client()
	shipper.post(context.Background(), []record{{line: []byte(`{}`)}})
	if got := attempts.Load(); got != 1 {
		t.Errorf("a rejected payload was sent %d times, want 1", got)
	}
	if shipper.failed.Load() != 1 {
		t.Errorf("failed = %d, want the batch counted as lost", shipper.failed.Load())
	}
}

func TestEnqueueShedsRatherThanBlockingWhenTheQueueIsFull(t *testing.T) {
	shipper := &Shipper{
		cfg:    &ShipperConfig{},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		queue:  make(chan record, 1),
	}
	if !shipper.enqueue("idp", []byte(`{"msg":"http_request","status":401}`)) {
		t.Fatal("the first record was not queued")
	}
	if shipper.enqueue("idp", []byte(`{"msg":"http_request","status":200}`)) {
		t.Fatal("a full queue reported success")
	}
	if got := shipper.dropped.Load(); got != 1 {
		t.Errorf("dropped = %d, want the loss to be counted, not hidden", got)
	}
	// Unstructured lines are skipped, not dropped: the counter has to
	// distinguish "we chose not to keep this" from "we lost it".
	if !shipper.enqueue("idp", []byte("plain text")) {
		t.Error("a plain text line was reported as a drop")
	}
	if got := shipper.skipped.Load(); got != 1 {
		t.Errorf("skipped = %d, want 1", got)
	}
}

// frame builds one Docker multiplexed log frame: a stream byte, three padding
// bytes, then the payload length as a big-endian uint32.
func frame(stream byte, payload string) []byte {
	header := make([]byte, 8)
	header[0] = stream
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	return append(header, payload...)
}
