package metrics

import (
	"bytes"
	"strings"
	"testing"
)

func TestCountersRenderInPrometheusTextFormat(t *testing.T) {
	registry := New()
	registry.Describe(RequestsTotal, "HTTP requests by route.")
	registry.Inc(RequestsTotal, map[string]string{"route": "transfer", "status": "2xx"})
	registry.Inc(RequestsTotal, map[string]string{"route": "transfer", "status": "2xx"})
	registry.Inc(RequestsTotal, map[string]string{"status": "4xx", "route": "transfer"})

	var buffer bytes.Buffer
	if err := registry.Write(&buffer); err != nil {
		t.Fatalf("Write: %v", err)
	}
	rendered := buffer.String()

	if !strings.Contains(rendered, "# HELP "+RequestsTotal+" HTTP requests by route.") {
		t.Errorf("missing help line:\n%s", rendered)
	}
	if !strings.Contains(rendered, "# TYPE "+RequestsTotal+" counter") {
		t.Errorf("missing type line:\n%s", rendered)
	}
	if !strings.Contains(rendered, `payment_requests_total{route="transfer",status="2xx"} 2`) {
		t.Errorf("the counter was not aggregated or labelled as expected:\n%s", rendered)
	}
}

// Label order must not depend on Go's map iteration order, or the same logical
// counter appears twice under two spellings.
func TestLabelOrderIsDeterministic(t *testing.T) {
	registry := New()
	for i := 0; i < 20; i++ {
		registry.Inc(UpstreamFailuresTotal, map[string]string{"outcome": "denied", "dependency": "account-service"})
	}

	var buffer bytes.Buffer
	if err := registry.Write(&buffer); err != nil {
		t.Fatalf("Write: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buffer.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly one series, got %d:\n%s", len(lines), buffer.String())
	}
	if !strings.Contains(lines[0], `{dependency="account-service",outcome="denied"} 20`) {
		t.Errorf("series = %q", lines[0])
	}
}

func TestSnapshotIsACopy(t *testing.T) {
	registry := New()
	registry.Inc(LedgerWritesTotal, nil)

	snapshot := registry.Snapshot()
	snapshot[LedgerWritesTotal] = 99

	if got := registry.Snapshot()[LedgerWritesTotal]; got != 1 {
		t.Errorf("the snapshot must not alias the registry, got %d", got)
	}
}

func TestStatusClassIsBounded(t *testing.T) {
	cases := map[int]string{0: "none", 100: "1xx", 200: "2xx", 301: "3xx", 404: "4xx", 503: "5xx"}
	for status, want := range cases {
		if got := StatusClass(status); got != want {
			t.Errorf("StatusClass(%d) = %q, want %q", status, got, want)
		}
	}
}
