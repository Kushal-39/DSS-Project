package httpapi

import (
	"context"
	"time"

	"paymentservice/internal/audit"
	"paymentservice/internal/metrics"
	"paymentservice/internal/mtls"
)

// RecordHandshakeRejection writes the audit record and counter for a TLS
// handshake the listener refused.
//
// It lives here, next to the rest of the audit vocabulary, rather than in the
// binary that wires it up, because it is the *only* record of the most common
// integration failure in this project: a caller with no client certificate (or
// one signed by the wrong CA) never reaches a handler, so nothing inside the
// application runs and nothing else could log it (telemetry/docs/integration.md
// §3 "Person 4" makes exactly this point).
//
// The record is a DENY with a stable reason, which is what turns "a service is
// calling us without a certificate" into a visible count on Person 6's
// dashboard instead of an empty page where the traffic should be.
func RecordHandshakeRejection(recorder *audit.Recorder, registry *metrics.Registry, rejection mtls.Rejection) {
	detail := map[string]any{
		"duration_ms": rejection.Duration.Milliseconds(),
	}
	if rejection.Err != nil {
		detail["error"] = rejection.Err.Error()
	}
	// Set only when a certificate was offered and rejected: the case worth
	// investigating, because the caller is inside the network and believes it
	// has credentials.
	if rejection.Identity != "" {
		detail["mtls_identity"] = rejection.Identity
		detail["mtls_subject"] = rejection.Subject
	}
	if rejection.Suppressed > 0 {
		detail["suppressed_since_last_report"] = rejection.Suppressed
	}

	if recorder != nil {
		recorder.Log(context.Background(), audit.Record{
			Event:       audit.EventMTLSRejected,
			Verdict:     audit.VerdictDeny,
			Reason:      rejection.Reason,
			RemoteAddr:  remoteHost(rejection.RemoteAddr),
			TraceParent: "",
			Detail:      detail,
		})
	}
	if registry != nil {
		registry.Inc(metrics.MTLSRejectionsTotal, map[string]string{"reason": rejection.Reason})
	}
}

// handshakeTimeout is exported for the binary so the listener and any probe
// agree on how long a TLS handshake may take.
const HandshakeTimeout = 5 * time.Second
