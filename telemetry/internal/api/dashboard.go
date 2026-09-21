package api

import (
	_ "embed"
	"net/http"
)

// dashboardHTML is the audit dashboard, embedded so the container ships a
// single self-contained artifact. It is deliberately dependency-free vanilla
// HTML/CSS/JS: a reviewer runs `docker compose up` and opens one page, with no
// Grafana provisioning, plugin install or datasource setup in between.
// Grafana remains available for ad-hoc exploration on top of Loki (see the
// compose file); this page is the deliverable's audit dashboard.
//
//go:embed dashboard.html
var dashboardHTML []byte

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The page is static; the data behind it is not. Never cache the shell
	// without revalidating, or a reviewer will stare at a stale dashboard.
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(dashboardHTML); err != nil {
		s.logger.Warn("dashboard_write_failed", "error", err)
	}
}
