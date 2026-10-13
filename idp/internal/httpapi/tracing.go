package httpapi

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var tracePattern = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)
var spanQueue = make(chan map[string]any, 512)
var exporterOnce sync.Once

func randomHex(size int) string {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (s *Server) traceRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parent := r.Header.Get("traceparent")
		parentID := ""
		traceID := randomHex(16)
		flags := "01"
		if tracePattern.MatchString(parent) {
			parts := strings.Split(parent, "-")
			if parts[1] != strings.Repeat("0", 32) && parts[2] != strings.Repeat("0", 16) {
				traceID, parentID, flags = parts[1], parts[2], parts[3]
			}
		}
		spanID := randomHex(8)
		current := "00-" + traceID + "-" + spanID + "-" + flags
		r.Header.Set("traceparent", current)
		w.Header().Set("traceparent", current)
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		if os.Getenv("OTLP_ENDPOINT") == "" || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			return
		}
		exporterOnce.Do(func() { go s.exportSpans() })
		code := "STATUS_CODE_OK"
		if rec.status >= 400 {
			code = "STATUS_CODE_ERROR"
		}
		span := map[string]any{"traceId": traceID, "spanId": spanID, "parentSpanId": parentID,
			"name": r.Method + " " + r.URL.Path, "kind": 2, "startTimeUnixNano": strconv.FormatInt(start.UnixNano(), 10),
			"endTimeUnixNano": strconv.FormatInt(time.Now().UnixNano(), 10), "status": map[string]string{"code": code}}
		select {
		case spanQueue <- span:
		default:
			s.logger.Warn("span_export_dropped")
		}
	})
}

func (s *Server) exportSpans() {
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for span := range spanQueue {
		payload := map[string]any{"resourceSpans": []any{map[string]any{
			"resource":   map[string]any{"attributes": []any{map[string]any{"key": "service.name", "value": map[string]string{"stringValue": "idp"}}}},
			"scopeSpans": []any{map[string]any{"spans": []any{span}}}}}}
		body, err := json.Marshal(payload)
		if err != nil {
			continue
		}
		req, err := http.NewRequest(http.MethodPost, os.Getenv("OTLP_ENDPOINT"), bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Telemetry-Token", os.Getenv("TELEMETRY_INGEST_TOKEN"))
		response, err := client.Do(req)
		if err != nil {
			s.logger.Warn("span_export_failed")
			continue
		}
		response.Body.Close()
	}
}
