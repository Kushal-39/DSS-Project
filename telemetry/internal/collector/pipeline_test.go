package collector

// This file drives the collector the way the container does: Run() against a
// Docker daemon and an ingest API. Nothing here is a stand-in for the code under
// test — the collector builds real requests, reads a real log stream and posts
// real batches; only the daemon's replies are synthetic, which is exactly what
// a daemon sends.
//
// It exists because the interesting behaviour of a collector is not any single
// function but the whole loop: which containers it decides to follow, what it
// does with a line that is not JSON, whether a dropped stream loses a decision,
// whether a shutdown loses what was already read, and whether it can tell
// anyone when it has gone blind. Those are the failures that leave an audit
// trail looking complete when it is not, and none of them are visible in a unit
// test of a helper.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a log sink that can be read while the component under test is
// still writing to it. A plain strings.Builder here is a data race, and the
// race detector would report it as one.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fakeContainer is one container the fake daemon reports and streams.
type fakeContainer struct {
	id     string
	name   string
	tty    bool
	labels map[string]string
	// lines are written to the log stream verbatim, in order.
	lines []string
	// gone makes the log endpoint answer 404, as it does for a container that
	// was recreated under a redeploy.
	gone bool
	// closeStream ends the stream after the lines instead of following it, so
	// the reconnect path can be exercised.
	closeStream bool
}

// fakeDaemon serves the subset of the Docker Engine API the collector uses.
type fakeDaemon struct {
	mu         sync.Mutex
	containers []fakeContainer
	// listFailures makes the next N container-list calls fail, to exercise the
	// discovery-failure path and the recovery from it.
	listFailures int
	logCalls     map[string]int
	// closing releases the handlers that are holding a followed stream open, so
	// a failing test cannot deadlock in server cleanup: a handler blocked on the
	// request context makes httptest wait for it forever.
	closing chan struct{}
}

func newFakeDaemon(t *testing.T, containers ...fakeContainer) *fakeDaemon {
	t.Helper()

	d := &fakeDaemon{
		containers: containers,
		logCalls:   map[string]int{},
		closing:    make(chan struct{}),
	}
	t.Cleanup(func() { close(d.closing) })
	return d
}

func (d *fakeDaemon) socketPath() string {
	// The client dials a unix socket; the test swaps only the dialer, so this
	// value is never resolved.
	return "fake-docker-socket"
}

func (d *fakeDaemon) client(t *testing.T) *Client {
	t.Helper()

	client := newTestClient(t, http.HandlerFunc(d.handle))
	client.socketPath = d.socketPath()
	return client
}

func (d *fakeDaemon) find(id string) *fakeContainer {
	for i := range d.containers {
		if d.containers[i].id == id {
			return &d.containers[i]
		}
	}
	return nil
}

func (d *fakeDaemon) calls(path string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.logCalls[path]
}

func (d *fakeDaemon) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/containers/json":
		d.mu.Lock()
		if d.listFailures > 0 {
			d.listFailures--
			d.mu.Unlock()
			http.Error(w, `{"message":"daemon is starting"}`, http.StatusServiceUnavailable)
			return
		}
		type summary struct {
			ID     string            `json:"Id"`
			Names  []string          `json:"Names"`
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		}
		payload := make([]summary, 0, len(d.containers))
		for _, container := range d.containers {
			payload = append(payload, summary{
				ID:     container.id,
				Names:  []string{"/" + container.name},
				Image:  "test/" + container.name,
				Labels: container.labels,
			})
		}
		d.mu.Unlock()
		writeJSON(w, payload)

	case strings.HasSuffix(r.URL.Path, "/json"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/containers/"), "/json")
		container := d.find(id)
		if container == nil {
			// Anything not in the list is this collector's own container: Run
			// inspects itself to learn which Compose project it belongs to.
			writeJSON(w, map[string]any{
				"Config": map[string]any{
					"Tty":    false,
					"Labels": map[string]string{"com.docker.compose.project": "dss-project"},
				},
			})
			return
		}
		writeJSON(w, map[string]any{
			"Config": map[string]any{"Tty": container.tty, "Labels": container.labels},
		})

	case strings.HasSuffix(r.URL.Path, "/logs"):
		d.mu.Lock()
		d.logCalls[r.URL.Path]++
		d.mu.Unlock()

		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/containers/"), "/logs")
		container := d.find(id)
		if container == nil || container.gone {
			http.Error(w, `{"message":"No such container"}`, http.StatusNotFound)
			return
		}

		flusher, _ := w.(http.Flusher)
		for _, line := range container.lines {
			if container.tty {
				// A TTY container's stream is not multiplexed.
				io.WriteString(w, line+"\n")
			} else {
				w.Write(frame(1, line+"\n"))
			}
			if flusher != nil {
				flusher.Flush()
			}
		}

		if container.closeStream {
			return
		}
		// follow=1: hold the stream open until the collector goes away, as a
		// real daemon does.
		select {
		case <-r.Context().Done():
		case <-d.closing:
		}

	default:
		http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
	}
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

// fakeIngest records what the collector posts and answers 202, as the audit API
// does for an accepted batch.
type fakeIngest struct {
	mu      sync.Mutex
	records []string
	tokens  []string
	bodies  int
	server  *httptest.Server
}

func newFakeIngest(t *testing.T) *fakeIngest {
	t.Helper()

	ingest := &fakeIngest{}
	ingest.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/audit/logs" {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		if r.Header.Get("Content-Type") != "application/x-ndjson" {
			http.Error(w, "unexpected content type "+r.Header.Get("Content-Type"), http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ingest.mu.Lock()
		defer ingest.mu.Unlock()
		ingest.bodies++
		ingest.tokens = append(ingest.tokens, r.Header.Get("X-Telemetry-Token"))
		for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
			if strings.TrimSpace(line) != "" {
				ingest.records = append(ingest.records, line)
			}
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"accepted":1}`)
	}))
	t.Cleanup(ingest.server.Close)
	return ingest
}

// waitFor polls until the condition holds, or fails the test with the reason
// given. The collector is asynchronous by nature, so every assertion about its
// output is a wait with a deadline rather than a sleep and a hope.
func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (f *fakeIngest) snapshot() ([]string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.records...), f.bodies
}

func testShipperConfig(endpoint string) *ShipperConfig {
	return &ShipperConfig{
		SocketPath:       "fake-docker-socket",
		Endpoint:         endpoint,
		Token:            "collector-token",
		LabelKey:         "com.docker.compose.project",
		Exclude:          []string{"telemetry"},
		FlushInterval:    50 * time.Millisecond,
		MaxBatch:         100,
		QueueSize:        128,
		DiscoverInterval: 100 * time.Millisecond,
		OverlapSeconds:   1,
	}
}

func projectLabels(service string) map[string]string {
	return map[string]string{
		"com.docker.compose.project": "dss-project",
		"com.docker.compose.service": service,
	}
}

func newPipelineShipper(t *testing.T, cfg *ShipperConfig, daemon *fakeDaemon) *Shipper {
	t.Helper()

	t.Setenv("TELEMETRY_SHIP_SELF_NAME", "dss-project-telemetry-collector-1")

	shipper := NewShipper(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	shipper.client = daemon.client(t)
	shipper.retryBackoff = time.Millisecond
	return shipper
}

// TestRunFollowsTheProjectAndShieldsThePipeline is the whole collector in one
// test: discovery, selection, streaming, enrichment, batching and delivery.
func TestRunFollowsTheProjectAndShieldsThePipeline(t *testing.T) {
	daemon := newFakeDaemon(t,
		fakeContainer{
			id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", name: "dss-project-idp-1",
			labels: projectLabels("idp"),
			lines: []string{
				`{"level":"info","msg":"http_request","http.response.status_code":401,"subject":"user123"}`,
				// A banner is not a structured record: Loki's job, not the
				// audit trail's.
				`IDP starting up, listening on :8080`,
			},
		},
		fakeContainer{
			id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", name: "dss-project-policy-engine-1",
			labels: projectLabels("policy-engine"),
			// A TTY container's stream is not framed.
			tty:   true,
			lines: []string{`{"service":"policy-engine","msg":"Decision Log","result":{"allow":false}}`},
		},
		fakeContainer{
			id: "cccccccccccccccccccccccccccccccccccccccc", name: "dss-project-telemetry-1",
			labels: projectLabels("telemetry"),
			lines:  []string{`{"msg":"http_request","path":"/v1/audit/logs"}`},
		},
		fakeContainer{
			id: "dddddddddddddddddddddddddddddddddddddddd", name: "dss-project-telemetry-collector-1",
			labels: projectLabels("telemetry-collector"),
			lines:  []string{`{"msg":"collector_following"}`},
		},
		fakeContainer{
			id: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", name: "unrelated",
			lines: []string{`{"msg":"not part of this project"}`},
		},
	)
	ingest := newFakeIngest(t)

	cfg := testShipperConfig(ingest.server.URL)
	shipper := newPipelineShipper(t, cfg, daemon)

	ctx, cancel := context.WithCancel(context.Background())
	// Registered as well as called: if an assertion fails first, the collector
	// must still stop before the fake daemon is torn down.
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = shipper.Run(ctx)
	}()

	waitFor(t, "the audit records to arrive", func() bool {
		records, _ := ingest.snapshot()
		return len(records) >= 2
	})

	// Let discovery settle so the ready report reflects the final follower set.
	waitFor(t, "two containers to be followed", func() bool { return shipper.followed.Load() == 2 })

	cancel()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}

	records, bodies := ingest.snapshot()
	if bodies == 0 {
		t.Fatal("the collector never posted a batch")
	}

	// Every record carries the service that produced it. The IdP does not name
	// itself in its log lines, so the collector supplies the field; the policy
	// engine does, and its own value must survive untouched.
	var sawIDP, sawPolicyEngine bool
	for _, record := range records {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(record), &decoded); err != nil {
			t.Fatalf("a posted record is not valid JSON: %q", record)
		}
		switch decoded["service"] {
		case "idp":
			sawIDP = true
			if decoded["subject"] != "user123" {
				t.Errorf("the idp record lost its fields: %s", record)
			}
		case "policy-engine":
			sawPolicyEngine = true
		case "telemetry", "telemetry-collector", "unrelated", "":
			t.Errorf("the collector shipped a record it must not: %s", record)
		}
	}
	if !sawIDP {
		t.Error("no record was attributed to the idp container: the audit trail would not know which service decided")
	}
	if !sawPolicyEngine {
		t.Error("no record was attributed to the policy engine: a TTY container's unframed stream was not read")
	}

	// The pipeline must not audit itself: its own request log is a record of
	// the observer, and shipping it feeds the collector lines that generate
	// more lines.
	for _, record := range records {
		if strings.Contains(record, "collector_following") {
			t.Errorf("the collector followed its own log stream: %s", record)
		}
	}

	if got := shipper.sent.Load(); got != int64(len(records)) {
		t.Errorf("shipped counter = %d but %d records were received", got, len(records))
	}
	if got := shipper.dropped.Load(); got != 0 {
		t.Errorf("dropped %d records while the ingest API was healthy", got)
	}
	if got := shipper.failed.Load(); got != 0 {
		t.Errorf("failed %d records while the ingest API was healthy", got)
	}
	if got := shipper.skipped.Load(); got < 1 {
		t.Error("the non-JSON banner was not counted as skipped: unstructured lines must be visible, not silent")
	}
	for _, token := range ingest.tokens {
		if token != "collector-token" {
			t.Errorf("a batch was posted with token %q; the ingest API authenticates collectors", token)
		}
	}

	// A collector that is following nothing must say so, and a healthy one must
	// report what it is following.
	ready, detail := shipper.readiness()
	if !ready {
		t.Errorf("not ready after a successful discovery: %s", detail)
	}
	if !strings.Contains(detail, "2 containers") {
		t.Errorf("readiness detail = %q, want the container count", detail)
	}
}

// TestRunReportsBlindnessAndRecovers covers the failure that matters most for
// an observability component: running, healthy, and collecting nothing.
func TestRunReportsBlindnessAndRecovers(t *testing.T) {
	daemon := newFakeDaemon(t, fakeContainer{
		id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", name: "dss-project-idp-1",
		labels: projectLabels("idp"),
		lines:  []string{`{"msg":"http_request"}`},
	})
	// The first two discoveries fail: the collector must keep running, report
	// that it cannot see anything, and pick the containers up when the daemon
	// answers again.
	daemon.listFailures = 2

	ingest := newFakeIngest(t)
	shipper := newPipelineShipper(t, testShipperConfig(ingest.server.URL), daemon)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = shipper.Run(ctx) }()
	defer cancel()

	// Until a discovery succeeds it is not ready, and the metric says so.
	handler := shipper.statusHandler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Errorf("before any successful discovery: readyz = %d, want 503", response.Code)
	}
	if body := response.Body.String(); !strings.Contains(body, "no container discovery has succeeded yet") {
		t.Errorf("readyz body = %s, want the reason the collector is not ready", body)
	}

	waitFor(t, "discovery to recover", func() bool {
		ready, _ := shipper.readiness()
		return ready
	})
	waitFor(t, "the idp record to be shipped", func() bool {
		records, _ := ingest.snapshot()
		return len(records) >= 1
	})

	if got := shipper.followed.Load(); got != 1 {
		t.Errorf("following %d containers after recovery, want 1", got)
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if body := response.Body.String(); !strings.Contains(body, "telemetry_collector_ready 1") {
		t.Errorf("/metrics does not report the collector as ready after recovery:\n%s", body)
	}
}

// TestRunShutdownFlushesWhatWasAlreadyRead proves the last claim the collector
// makes about itself: cancelling it does not discard the decisions already in
// hand. The flush interval is set well beyond the test's lifetime, so anything
// that arrives can only come from the shutdown flush.
func TestRunShutdownFlushesWhatWasAlreadyRead(t *testing.T) {
	daemon := newFakeDaemon(t, fakeContainer{
		id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", name: "dss-project-idp-1",
		labels: projectLabels("idp"),
		lines:  []string{`{"msg":"http_request","http.response.status_code":403}`},
	})
	ingest := newFakeIngest(t)

	cfg := testShipperConfig(ingest.server.URL)
	cfg.FlushInterval = 30 * time.Second
	cfg.MaxBatch = 1000
	shipper := newPipelineShipper(t, cfg, daemon)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = shipper.Run(ctx)
	}()

	// Wait only for the line to have been read and accepted, not for it to be
	// sent. The queue itself is the wrong thing to observe: the flush loop
	// drains it into its pending batch immediately, so an empty queue means
	// "already read", not "never read".
	waitFor(t, "the line to be read into the pipeline", func() bool { return shipper.queued.Load() >= 1 })
	if _, bodies := ingest.snapshot(); bodies != 0 {
		t.Fatalf("a batch was posted before the flush interval elapsed, so this test proves nothing")
	}
	if got := shipper.sent.Load(); got != 0 {
		t.Fatalf("sent = %d before the flush interval elapsed", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}

	records, _ := ingest.snapshot()
	if len(records) == 0 {
		t.Fatal("the decision that was already read was lost on shutdown")
	}
	if shipper.sent.Load() == 0 {
		t.Error("the shutdown flush did not count the shipped records")
	}
	if got := shipper.queued.Load(); got < 1 {
		t.Errorf("queued = %d, but a record was read", got)
	}
}

// TestFollowReconnectsAndReportsAContainerThatVanished covers the two ways a log
// stream ends: a dropped stream, which must be re-read with overlap so no
// decision is lost, and a container that no longer exists, which must be
// abandoned rather than retried forever.
func TestFollowReconnectsAndReportsAContainerThatVanished(t *testing.T) {
	daemon := newFakeDaemon(t,
		fakeContainer{
			id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", name: "dss-project-idp-1",
			labels:      projectLabels("idp"),
			lines:       []string{`{"msg":"http_request"}`},
			closeStream: true,
		},
		fakeContainer{
			id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", name: "dss-project-api-1",
			labels: projectLabels("api"),
			gone:   true,
		},
	)

	logs := &syncBuffer{}
	shipper := &Shipper{
		cfg: &ShipperConfig{
			Endpoint:         "http://127.0.0.1:1",
			Token:            "t",
			LabelKey:         "com.docker.compose.project",
			LabelValue:       "dss-project",
			ServicePrefix:    "dss-project-",
			Exclude:          []string{"telemetry"},
			DiscoverInterval: 50 * time.Millisecond,
			OverlapSeconds:   3,
			QueueSize:        8,
		},
		client: daemon.client(t),
		logger: slog.New(slog.NewTextHandler(logs, nil)),
		// Delivery is irrelevant here; the ingest endpoint is deliberately
		// unreachable and the queue is never drained.
		http:         &http.Client{Timeout: time.Second},
		retryBackoff: time.Millisecond,
		queue:        make(chan record, 8),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go shipper.discoverLoop(ctx, "self-id-not-matching-anything", "")

	// The stream ends after its lines, so the follower must come back for more.
	waitFor(t, "the idp stream to be re-opened", func() bool {
		return daemon.calls("/containers/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/logs") >= 2
	})

	waitFor(t, "the vanished container to be reported", func() bool {
		return strings.Contains(logs.String(), "collector_container_gone")
	})
	if !strings.Contains(logs.String(), `service=api`) {
		t.Errorf("the vanished container was reported without naming the service:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "collector_discovery_failed") {
		// Discovery never failed in this test, so a failure log would mean the
		// two paths are confused.
		t.Errorf("discovery reported a failure it did not have:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "collector_stream_lost") {
		t.Errorf("a stream that ended without the container going away was not reported:\n%s", logs.String())
	}
}
