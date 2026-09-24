// Package metrics is the counter set this service exposes on /metrics.
//
// It is hand-rolled (a mutex and a map) rather than pulling in a client
// library: the component needs a handful of counters, and every dependency
// added to the money path is a dependency in the money path. Person 6's
// platform already scrapes /metrics on the other services, so the format is
// Prometheus text exposition.
//
// Cardinality discipline: label values are only ever drawn from fixed sets
// (route, status class, reason, dependency). Nothing user-supplied — no user
// id, no amount, no account, no arbitrary path — is used as a label, because a
// label with unbounded values turns a metrics endpoint into a memory leak.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// Registry accumulates counters.
type Registry struct {
	mu       sync.Mutex
	counters map[string]int64
	help     map[string]string
}

// New builds an empty Registry.
func New() *Registry {
	return &Registry{counters: map[string]int64{}, help: map[string]string{}}
}

// Counter names.
const (
	// RequestsTotal counts HTTP requests by route and status class.
	RequestsTotal = "payment_requests_total"
	// MTLSRejectionsTotal counts refused TLS handshakes by reason. These never
	// reach a handler, so this counter is often the only mechanical evidence
	// that a caller is misconfigured.
	MTLSRejectionsTotal = "payment_mtls_rejections_total"
	// PolicyDecisionsTotal counts policy verdicts.
	PolicyDecisionsTotal = "payment_policy_decisions_total"
	// TransfersTotal counts business outcomes.
	TransfersTotal = "payment_transfers_total"
	// UpstreamFailuresTotal counts failed calls to a dependency.
	UpstreamFailuresTotal = "payment_upstream_failures_total"
	// LedgerWritesTotal counts ledger rows written.
	LedgerWritesTotal = "payment_ledger_writes_total"
	// SpanExportFailuresTotal counts dropped span exports. Spans are
	// best-effort by design; this is how "best-effort" stays visible.
	SpanExportFailuresTotal = "payment_span_export_failures_total"
)

// Describe registers the help text for a counter family.
func (r *Registry) Describe(name, help string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.help[name] = help
}

// Inc adds one to the counter identified by name and labels.
func (r *Registry) Inc(name string, labels map[string]string) {
	r.Add(name, labels, 1)
}

// Add adds delta to the counter identified by name and labels.
func (r *Registry) Add(name string, labels map[string]string, delta int64) {
	key := encode(name, labels)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counters[key] += delta
}

// Snapshot returns a copy of the current counters.
func (r *Registry) Snapshot() map[string]int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]int64, len(r.counters))
	for key, value := range r.counters {
		out[key] = value
	}
	return out
}

// Write renders the counters in Prometheus text exposition format.
//
// The method is deliberately not named WriteTo: that name is io.WriterTo's, and
// satisfying that interface with a different signature is a trap for whoever
// passes a Registry to anything expecting one.
//
// Families are emitted in a stable order (sorted) so two scrapes of an
// unchanged service produce byte-identical output apart from the values, which
// is what makes a diff of the endpoint readable.
func (r *Registry) Write(w io.Writer) error {
	r.mu.Lock()
	keys := make([]string, 0, len(r.counters))
	for key := range r.counters {
		keys = append(keys, key)
	}
	snapshot := make(map[string]int64, len(r.counters))
	for key, value := range r.counters {
		snapshot[key] = value
	}
	help := make(map[string]string, len(r.help))
	for name, text := range r.help {
		help[name] = text
	}
	r.mu.Unlock()

	sort.Strings(keys)

	described := map[string]bool{}
	for _, key := range keys {
		name, _ := split(key)
		if text, ok := help[name]; ok && !described[name] {
			described[name] = true
			if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, text, name); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s %d\n", key, snapshot[key]); err != nil {
			return err
		}
	}
	return nil
}

// encode renders `name{label="value",…}` with labels sorted by key. Sorting is
// not cosmetic: without it the same logical counter can appear under two keys.
func encode(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var builder strings.Builder
	builder.WriteString(name)
	builder.WriteString("{")
	for index, key := range keys {
		if index > 0 {
			builder.WriteString(",")
		}
		fmt.Fprintf(&builder, "%s=%q", key, labels[key])
	}
	builder.WriteString("}")
	return builder.String()
}

func split(key string) (string, string) {
	if index := strings.IndexByte(key, '{'); index >= 0 {
		return key[:index], key[index:]
	}
	return key, ""
}

// StatusClass turns a status code into a bounded label value ("2xx", "4xx").
func StatusClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	case status >= 100:
		return "1xx"
	default:
		return "none"
	}
}
