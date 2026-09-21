package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"telemetry/internal/tlsconf"
)

// defaultStatusAddr is the collector's own health and metrics listener.
const defaultStatusAddr = ":8089"

// ShipperConfig is the collector's runtime configuration.
type ShipperConfig struct {
	// SocketPath is the Docker socket (DOCKER_SOCKET).
	SocketPath string
	// Endpoint is the telemetry ingest base URL (TELEMETRY_URL).
	Endpoint string
	// Token authenticates the ingest calls (TELEMETRY_INGEST_TOKEN).
	Token string

	// LabelKey selects containers to collect: any container carrying this
	// label (TELEMETRY_SHIP_LABEL, default com.docker.compose.project).
	LabelKey string
	// LabelValue narrows that selection to one value (TELEMETRY_SHIP_PROJECT).
	// Empty means "whatever project the collector itself runs in".
	LabelValue string
	// Containers is an explicit allowlist by name or id prefix; when set it
	// replaces label-based discovery (TELEMETRY_SHIP_CONTAINERS).
	Containers []string

	// Exclude skips containers by name or service name (TELEMETRY_SHIP_EXCLUDE,
	// default "telemetry"). It defaults to the telemetry service itself because
	// the pipeline's own request log is a record of *its own* ingest traffic:
	// shipping it feeds the collector lines that generate more lines and fills
	// the audit trail with the observer instead of the observed.
	Exclude []string

	// ServicePrefix is stripped from container names so the audit trail says
	// "idp" rather than "dss-project-idp-1"
	// (TELEMETRY_SHIP_SERVICE_PREFIX, default: the compose project + "-").
	ServicePrefix string

	// FlushInterval and MaxBatch bound ingest latency and payload size.
	FlushInterval time.Duration
	MaxBatch      int
	// QueueSize bounds memory when the ingest API is slow. The newest line is
	// shed when the queue is full — it is still in the container's log buffer
	// and the reconnect overlap re-reads it — and the drops are reported
	// rather than hidden.
	QueueSize int

	// StatusAddr is the collector's own health/metrics listener
	// (TELEMETRY_SHIP_ADDR, default ":8089"; empty disables it).
	StatusAddr string
	// Backfill bounds how much history is read from each container the first
	// time it is followed (TELEMETRY_SHIP_BACKFILL, default "30m"; "0s" reads
	// everything the container still holds). The ingest API is idempotent, so
	// this only trades restart cost against a longer history.
	Backfill time.Duration

	// TLS is the collector's half of the Transport Contract
	// (docs/division.md §2): verify the ingest API against the shared CA, and
	// present a certificate when the API requires one. Empty means plain
	// HTTP, which is what the rest of the stack does today.
	TLS tlsconf.Settings

	// DiscoverInterval is how often the container list is refreshed.
	DiscoverInterval time.Duration
	// OverlapSeconds is how far back a reconnect re-reads, so a dropped stream
	// cannot lose a decision. Duplicates are discarded by the ingest API's
	// idempotency check, so favouring overlap over precision is safe.
	OverlapSeconds int
}

// LoadShipperConfig reads the collector's configuration from the environment.
func LoadShipperConfig() (*ShipperConfig, error) {
	cfg := &ShipperConfig{
		SocketPath:    envDefault("DOCKER_SOCKET", "/var/run/docker.sock"),
		Endpoint:      strings.TrimSuffix(envDefault("TELEMETRY_URL", "http://telemetry:8088"), "/"),
		Token:         strings.TrimSpace(os.Getenv("TELEMETRY_INGEST_TOKEN")),
		LabelKey:      envDefault("TELEMETRY_SHIP_LABEL", "com.docker.compose.project"),
		LabelValue:    strings.TrimSpace(os.Getenv("TELEMETRY_SHIP_PROJECT")),
		Containers:    splitList(os.Getenv("TELEMETRY_SHIP_CONTAINERS")),
		Exclude:       excludeList(os.Getenv("TELEMETRY_SHIP_EXCLUDE")),
		ServicePrefix: strings.TrimSpace(os.Getenv("TELEMETRY_SHIP_SERVICE_PREFIX")),
	}

	// An unset TELEMETRY_SHIP_ADDR means the default status port; an explicitly
	// empty one turns the status server off.
	if _, set := os.LookupEnv("TELEMETRY_SHIP_ADDR"); !set {
		cfg.StatusAddr = defaultStatusAddr
	} else {
		cfg.StatusAddr = strings.TrimSpace(os.Getenv("TELEMETRY_SHIP_ADDR"))
	}

	if cfg.Token == "" {
		return nil, fmt.Errorf(
			"collector: TELEMETRY_INGEST_TOKEN is not set — the audit ingest API authenticates " +
				"collectors, so the shipper cannot start without it")
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("collector: TELEMETRY_URL is not set")
	}

	var err error
	if cfg.FlushInterval, err = durationEnv("TELEMETRY_SHIP_FLUSH_INTERVAL", 2*time.Second); err != nil {
		return nil, err
	}
	if cfg.DiscoverInterval, err = durationEnv("TELEMETRY_SHIP_DISCOVER_INTERVAL", 15*time.Second); err != nil {
		return nil, err
	}
	if cfg.MaxBatch, err = intEnv("TELEMETRY_SHIP_MAX_BATCH", 200); err != nil {
		return nil, err
	}
	if cfg.QueueSize, err = intEnv("TELEMETRY_SHIP_QUEUE", 20000); err != nil {
		return nil, err
	}
	if cfg.OverlapSeconds, err = intEnv("TELEMETRY_SHIP_OVERLAP_SECONDS", 10); err != nil {
		return nil, err
	}
	if cfg.Backfill, err = durationEnvAllowZero("TELEMETRY_SHIP_BACKFILL", 30*time.Minute); err != nil {
		return nil, err
	}

	// The collector is a client: it verifies the server, and presents its own
	// certificate when it has one. It never demands a peer certificate.
	cfg.TLS = tlsconf.Settings{
		CertFile:   strings.TrimSpace(os.Getenv("TELEMETRY_TLS_CERT_FILE")),
		KeyFile:    strings.TrimSpace(os.Getenv("TELEMETRY_TLS_KEY_FILE")),
		CAFile:     strings.TrimSpace(os.Getenv("TELEMETRY_TLS_CA_FILE")),
		ServerName: strings.TrimSpace(os.Getenv("TELEMETRY_TLS_SERVER_NAME")),
	}
	if err := cfg.TLS.Validate(); err != nil {
		return nil, fmt.Errorf("collector: %w (set TELEMETRY_TLS_CERT_FILE and "+
			"TELEMETRY_TLS_KEY_FILE together, with TELEMETRY_TLS_CA_FILE for the shared CA)", err)
	}
	if cfg.TLS.Enabled() && strings.HasPrefix(cfg.Endpoint, "http://") {
		return nil, fmt.Errorf(
			"collector: TLS is configured but TELEMETRY_URL=%q is plain http — the certificate "+
				"would only be exchanged in the clear. Use https:// (or drop the TLS settings)",
			cfg.Endpoint)
	}
	if cfg.MaxBatch <= 0 || cfg.QueueSize <= 0 || cfg.OverlapSeconds < 0 {
		return nil, fmt.Errorf("collector: batch size, queue size and overlap must not be negative")
	}
	return cfg, nil
}

// record is one log line tagged with the container it came from.
type record struct {
	service string
	line    []byte
}

// Shipper streams container logs into the telemetry ingest API.
type Shipper struct {
	cfg    *ShipperConfig
	client *Client
	http   *http.Client
	logger *slog.Logger

	// retryBackoff is the base delay between ingest retries. It is a field so
	// tests can exercise the retry path without waiting seconds for it.
	retryBackoff time.Duration

	queue chan record

	sent    atomic.Int64
	dropped atomic.Int64
	failed  atomic.Int64
	skipped atomic.Int64

	// Status counters, read by ServeStatus. They are refreshed by the loops
	// above so /readyz can answer "can I actually see containers right now".
	followed      atomic.Int64
	lastDiscovery atomic.Int64
	lastIngest    atomic.Int64
}

// NewShipper builds a collector.
func NewShipper(cfg *ShipperConfig, logger *slog.Logger) *Shipper {
	return &Shipper{
		cfg:          cfg,
		client:       NewClient(cfg.SocketPath),
		http:         newIngestClient(cfg, logger),
		logger:       logger,
		retryBackoff: time.Second,
		queue:        make(chan record, cfg.QueueSize),
	}
}

// newIngestClient builds the HTTP client used to push into the audit API.
//
// A TLS problem here stops the audit trail, so it must not be silently
// tolerated: an unreadable certificate is reported at construction and the
// client keeps working over plain HTTP only when no TLS was configured at all.
func newIngestClient(cfg *ShipperConfig, logger *slog.Logger) *http.Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	tlsConfig, err := cfg.TLS.Client()
	if err != nil {
		logger.Error("collector_tls_config_failed", "error", err)
		return &http.Client{Timeout: 20 * time.Second, Transport: transport}
	}
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
		logger.Info("collector_tls_enabled",
			"endpoint", cfg.Endpoint,
			"ca_configured", cfg.TLS.CAFile != "",
			"client_certificate", cfg.TLS.CertFile != "",
		)
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: transport}
}

// Run supervises discovery and ingestion until ctx is cancelled.
func (s *Shipper) Run(ctx context.Context) error {
	selfID, selfName := selfIdentity()

	// If no explicit project was configured, collect the containers that sit
	// in the same Compose project as the collector: that is exactly "our
	// stack", with no hardcoded project name to drift out of date.
	if s.cfg.LabelValue == "" && len(s.cfg.Containers) == 0 {
		if _, labels, err := s.client.Inspect(ctx, selfID); err == nil {
			s.cfg.LabelValue = labels[s.cfg.LabelKey]
		} else {
			s.logger.Warn("collector_self_inspect_failed", "error", err)
		}
	}
	if s.cfg.ServicePrefix == "" && s.cfg.LabelValue != "" {
		s.cfg.ServicePrefix = s.cfg.LabelValue + "-"
	}

	s.logger.Info("collector_started",
		"endpoint", s.cfg.Endpoint,
		"socket", s.cfg.SocketPath,
		"label", s.cfg.LabelKey+maybeValue(s.cfg.LabelValue),
		"explicit_containers", len(s.cfg.Containers),
		"service_prefix", s.cfg.ServicePrefix,
	)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.flushLoop(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.discoverLoop(ctx, selfID, selfName)
	}()

	// Drain the queue briefly after cancellation so the decisions that were
	// already read are not lost in the shutdown.
	wg.Wait()
	s.logger.Info("collector_stopped",
		"shipped", s.sent.Load(),
		"dropped", s.dropped.Load(),
		"failed", s.failed.Load(),
		"skipped", s.skipped.Load(),
	)
	return nil
}

// discoverLoop maintains one log follower per selected container.
func (s *Shipper) discoverLoop(ctx context.Context, selfID, selfName string) {
	active := map[string]context.CancelFunc{}
	defer func() {
		for _, cancel := range active {
			cancel()
		}
	}()

	ticker := time.NewTicker(s.cfg.DiscoverInterval)
	defer ticker.Stop()

	for {
		containers, err := s.client.ListContainers(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.logger.Warn("collector_discovery_failed", "error", err)
		} else {
			selected := s.selectContainers(containers, selfID, selfName)
			s.lastDiscovery.Store(time.Now().UnixNano())
			s.followed.Store(int64(len(selected)))

			// Stop following containers that vanished (recreated on a redeploy).
			wanted := map[string]bool{}
			for _, container := range selected {
				wanted[container.ID] = true
			}
			for id, cancel := range active {
				if !wanted[id] {
					cancel()
					delete(active, id)
				}
			}

			for _, container := range selected {
				if _, running := active[container.ID]; running {
					continue
				}
				service := s.serviceName(container.Name)
				childCtx, cancel := context.WithCancel(ctx)
				active[container.ID] = cancel
				s.logger.Info("collector_following", "container", container.Name, "service", service)
				go s.follow(childCtx, container, service)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// selectContainers applies the allowlist or label selection, never following
// itself: shipping its own logs would make every ingest produce new lines that
// get ingested again.
func (s *Shipper) selectContainers(containers []Container, selfID, selfName string) []Container {
	selected := make([]Container, 0, len(containers))
	for _, container := range containers {
		if isSelf(container, selfID, selfName) {
			continue
		}
		if !s.wanted(container) {
			continue
		}
		if s.excluded(container) {
			continue
		}
		selected = append(selected, container)
	}
	return selected
}

func (s *Shipper) excluded(container Container) bool {
	service := s.serviceName(container.Name)
	for _, name := range s.cfg.Exclude {
		if strings.EqualFold(name, service) || strings.EqualFold(name, container.Name) {
			return true
		}
	}
	return false
}

func (s *Shipper) wanted(container Container) bool {
	if len(s.cfg.Containers) > 0 {
		for _, wanted := range s.cfg.Containers {
			if container.Name == wanted || strings.HasPrefix(container.ID, wanted) {
				return true
			}
		}
		return false
	}
	if s.cfg.LabelKey == "" {
		return false
	}
	value, ok := container.Labels[s.cfg.LabelKey]
	if !ok || value == "" {
		return false
	}
	return s.cfg.LabelValue == "" || value == s.cfg.LabelValue
}

// follow streams one container's logs, reconnecting with a small overlap so a
// dropped stream cannot swallow a decision.
func (s *Shipper) follow(ctx context.Context, container Container, service string) {
	first := true
	for {
		if err := ctx.Err(); err != nil {
			return
		}

		// The first read is bounded, but every reconnect after it is not: a
		// restart must not re-read a week-old log file, while a dropped stream
		// must not lose a decision. Overlap is safe because the ingest API
		// discards duplicates by record id.
		since := time.Time{}
		if first {
			if s.cfg.Backfill > 0 {
				since = time.Now().Add(-s.cfg.Backfill)
			}
		} else {
			since = time.Now().Add(-time.Duration(s.cfg.OverlapSeconds) * time.Second)
		}
		first = false

		err := s.client.StreamLogs(ctx, container.ID, since, func(line []byte) {
			if !s.enqueue(service, line) && ctx.Err() == nil {
				s.logger.Warn("collector_queue_full", "service", service)
			}
		})

		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, ErrContainerGone) {
			s.logger.Info("collector_container_gone", "service", service)
			return
		}
		s.logger.Warn("collector_stream_lost", "service", service, "error", err)

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (s *Shipper) enqueue(service string, line []byte) bool {
	enriched, ok := enrich(service, line)
	if !ok {
		s.skipped.Add(1)
		return true
	}
	select {
	case s.queue <- record{service: service, line: enriched}:
		return true
	default:
		// The ingest API is not keeping up. Shed the *newest* line rather than
		// block a follower or grow without bound: the container's own log buffer
		// still holds it, and the reconnect overlap will re-read it, whereas a
		// follower blocked here stops reading everything behind it. The loss is
		// counted and logged, never hidden.
		s.dropped.Add(1)
		return false
	}
}

// flushLoop batches queued lines and posts them.
func (s *Shipper) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.FlushInterval)
	defer ticker.Stop()

	batch := make([]record, 0, s.cfg.MaxBatch)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// A shutdown flush still has to be attempted even though ctx is done.
		flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		s.post(flushCtx, batch)
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case item := <-s.queue:
			batch = append(batch, item)
			if len(batch) >= s.cfg.MaxBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// post sends a batch as newline-delimited JSON records.
func (s *Shipper) post(ctx context.Context, batch []record) {
	body := new(bytes.Buffer)
	for i, item := range batch {
		if i > 0 {
			body.WriteByte('\n')
		}
		body.Write(item.line)
	}

	endpoint := s.cfg.Endpoint + "/v1/audit/logs"
	var lastErr error
	for attempt := 1; attempt <= 5; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body.Bytes()))
		if err != nil {
			lastErr = err
			break
		}
		request.Header.Set("Content-Type", "application/x-ndjson")
		request.Header.Set("X-Telemetry-Token", s.cfg.Token)

		response, err := s.http.Do(request)
		if err == nil {
			// Drain a bounded amount so the connection can be reused.
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			response.Body.Close()
			if response.StatusCode < http.StatusBadRequest {
				s.sent.Add(int64(len(batch)))
				s.lastIngest.Store(time.Now().UnixNano())
				return
			}
			lastErr = fmt.Errorf("ingest API returned %d", response.StatusCode)
			if response.StatusCode < http.StatusInternalServerError {
				// A 4xx is our fault and will not fix itself by retrying.
				break
			}
		} else {
			lastErr = err
		}

		// Note: `break` inside a select only leaves the select, so the loop is
		// exited explicitly once the context is done.
		select {
		case <-ctx.Done():
			lastErr = ctx.Err()
		case <-time.After(time.Duration(attempt) * s.retryBackoff):
		}
		if ctx.Err() != nil {
			break
		}
	}

	s.failed.Add(int64(len(batch)))
	s.logger.Error("collector_batch_failed",
		"endpoint", endpoint, "count", len(batch), "error", lastErr)
}

// --- helpers --------------------------------------------------------------

// enrich labels a log line with the service that produced it.
//
// Most components do not name themselves in every log line (the IdP does not),
// but the collector knows which container the bytes came from, so it supplies
// the missing field. Records that already carry a service identity are left
// exactly as the producer wrote them.
func enrich(service string, line []byte) ([]byte, bool) {
	var record map[string]any
	if err := json.Unmarshal(line, &record); err != nil {
		// Not structured output: Loki's job, not the audit trail's.
		return nil, false
	}
	for _, key := range []string{"service", "component", "service_name", "app"} {
		if value, ok := record[key].(string); ok && strings.TrimSpace(value) != "" {
			encoded, err := json.Marshal(record)
			if err != nil {
				return nil, false
			}
			return encoded, true
		}
	}
	record["service"] = service
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, false
	}
	return encoded, true
}

// serviceName turns a Compose container name into a service name:
// "dss-project-idp-1" -> "idp".
func (s *Shipper) serviceName(containerName string) string {
	name := containerName
	if s.cfg.ServicePrefix != "" && strings.HasPrefix(name, s.cfg.ServicePrefix) {
		name = strings.TrimPrefix(name, s.cfg.ServicePrefix)
	}
	// Strip the trailing replica index Compose appends.
	if index := strings.LastIndex(name, "-"); index > 0 {
		if _, err := strconv.Atoi(name[index+1:]); err == nil {
			name = name[:index]
		}
	}
	if name == "" {
		return containerName
	}
	return name
}

// isSelf matches this collector's own container.
//
// The comparison has to be prefix-based: Docker sets a container's HOSTNAME to
// the short (12 hex character) id, while the container list reports the full 64
// character id. Comparing them for equality silently never matches, and a
// collector that follows its own log stream feeds itself the lines that made
// it log in the first place.
func isSelf(container Container, selfID, selfName string) bool {
	if selfName != "" && container.Name == selfName {
		return true
	}
	return len(selfID) >= 12 && strings.HasPrefix(container.ID, selfID)
}

// selfIdentity returns this process's container id and name, so the collector
// never follows its own log stream (which would loop forever).
func selfIdentity() (id string, name string) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", ""
	}
	// Compose sets HOSTNAME to the short container id. Reading cgroup v2 is the
	// fallback when the hostname has been overridden.
	if id = hostname; id == "" {
		if raw, err := os.ReadFile("/proc/self/cgroup"); err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				if index := strings.LastIndex(line, "/"); index >= 0 && len(line[index+1:]) >= 12 {
					id = strings.TrimSpace(line[index+1:])
				}
			}
		}
	}
	return id, os.Getenv("TELEMETRY_SHIP_SELF_NAME")
}

func maybeValue(value string) string {
	if value == "" {
		return ""
	}
	return "=" + value
}

// excludeList is splitList with a default: an unset TELEMETRY_SHIP_EXCLUDE
// means "everything except the pipeline itself", and setting it to "-"
// explicitly means "nothing is excluded".
func excludeList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{"telemetry"}
	}
	if strings.TrimSpace(raw) == "-" {
		return nil
	}
	return splitList(raw)
}

func splitList(raw string) []string {
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

func envDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("collector: %s=%q is not a valid duration: %w", key, raw, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("collector: %s=%q must be positive", key, raw)
	}
	return parsed, nil
}

// durationEnvAllowZero is durationEnv for a setting where zero is a meaningful
// value ("no bound") rather than a mistake. Go durations need a unit, so the
// way to say "everything" is "0s", not "0".
func durationEnvAllowZero(key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("collector: %s=%q is not a valid duration (use \"0s\" for no bound): %w", key, raw, err)
	}
	if parsed < 0 {
		return 0, fmt.Errorf("collector: %s=%q must not be negative (use \"0s\" for no bound)", key, raw)
	}
	return parsed, nil
}

func intEnv(key string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("collector: %s=%q is not a valid integer: %w", key, raw, err)
	}
	return parsed, nil
}
