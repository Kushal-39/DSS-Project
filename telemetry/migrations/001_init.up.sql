-- 001_init.up.sql
-- Telemetry schema bootstrap (Person 6 — Observability, Tracing, Central Logging).
--
-- Database-per-Service (docs/database.md §2): telemetry owns these two tables
-- exclusively. No other service reads or writes them, and telemetry never
-- reaches into another service's schema. Components feed this pipeline over
-- the ingest API (HTTP), which is the only integration surface.
--
-- Two tables, because there are two things worth storing:
--
--   audit_events  the security decisions: who attempted what, and what the
--                 system decided (PERMIT / DENY / ERROR / INFO). This is what
--                 the dashboard's "blocked requests" and "unauthorized access
--                 attempts" counters are built from.
--   spans         the OpenTelemetry spans, so a decision can be joined to the
--                 distributed flow it happened inside via the W3C trace id.

CREATE TABLE IF NOT EXISTS audit_events (
    -- Stable, content-derived id: re-ingesting the same record (collector
    -- retry, container restart re-reading a log file) must not double-count
    -- it in the audit trail.
    event_id      TEXT        PRIMARY KEY,
    occurred_at   TIMESTAMPTZ NOT NULL,
    category      TEXT        NOT NULL,
    decision      TEXT        NOT NULL,
    reason        TEXT        NOT NULL DEFAULT '',
    service       TEXT        NOT NULL,
    event_type    TEXT        NOT NULL DEFAULT '',
    subject       TEXT        NOT NULL DEFAULT '',
    roles         TEXT[]      NOT NULL DEFAULT '{}',
    method        TEXT        NOT NULL DEFAULT '',
    path          TEXT        NOT NULL DEFAULT '',
    status        INTEGER     NOT NULL DEFAULT 0,
    remote_addr   TEXT        NOT NULL DEFAULT '',
    -- The W3C trace context every component already propagates (docs/flow.md
    -- §3). It is the join key between the audit trail and the spans.
    trace_id      TEXT        NOT NULL DEFAULT '',
    span_id       TEXT        NOT NULL DEFAULT '',
    request_id    TEXT        NOT NULL DEFAULT '',
    duration_ms   BIGINT      NOT NULL DEFAULT 0,
    message       TEXT        NOT NULL DEFAULT '',
    action        TEXT        NOT NULL DEFAULT '',
    resource      TEXT        NOT NULL DEFAULT '',
    -- Which ingestion path produced this row (push / docker / otlp), so a
    -- suspicious gap in the trail can be traced to the collector that fed it.
    ingested_via  TEXT        NOT NULL DEFAULT '',
    -- The original producer payload, bounded at 8 KiB in the normaliser.
    -- Kept for forensics: when a decision is questioned, the raw record is
    -- the evidence.
    raw           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    ingested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT audit_events_category_check
        CHECK (category IN ('AUTH', 'AUTHZ', 'ACCESS', 'RATE_LIMIT', 'ERROR', 'LOG')),
    CONSTRAINT audit_events_decision_check
        CHECK (decision IN ('PERMIT', 'DENY', 'ERROR', 'INFO'))
);

-- Every dashboard panel filters on the window first, then one dimension.
CREATE INDEX IF NOT EXISTS audit_events_occurred_at_idx ON audit_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_decision_idx    ON audit_events (decision, occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_category_idx    ON audit_events (category, occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_service_idx     ON audit_events (service, occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_reason_idx      ON audit_events (reason, occurred_at DESC);
-- The trace join: "show me every decision that happened inside trace X".
CREATE INDEX IF NOT EXISTS audit_events_trace_id_idx    ON audit_events (trace_id) WHERE trace_id <> '';
CREATE INDEX IF NOT EXISTS audit_events_subject_idx     ON audit_events (subject, occurred_at DESC) WHERE subject <> '';

COMMENT ON TABLE audit_events IS
    'Security decision audit trail owned by the telemetry service. Written only via the ingest API.';
COMMENT ON COLUMN audit_events.event_id IS
    'Content-derived stable id; makes re-ingestion idempotent.';
COMMENT ON COLUMN audit_events.raw IS
    'Original producer payload for forensics, bounded to 8 KiB by the normaliser.';

CREATE TABLE IF NOT EXISTS spans (
    trace_id       TEXT        NOT NULL,
    span_id        TEXT        NOT NULL,
    parent_span_id TEXT        NOT NULL DEFAULT '',
    service        TEXT        NOT NULL,
    name           TEXT        NOT NULL,
    started_at     TIMESTAMPTZ NOT NULL,
    -- NULL for a span that has not ended (an in-flight request observed by a
    -- streaming collector).
    ended_at       TIMESTAMPTZ,
    duration_ns    BIGINT      NOT NULL DEFAULT 0,
    status         TEXT        NOT NULL DEFAULT '',
    attributes     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    ingested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- A span id is only unique within its trace.
    PRIMARY KEY (trace_id, span_id)
);

CREATE INDEX IF NOT EXISTS spans_started_at_idx ON spans (started_at DESC);
CREATE INDEX IF NOT EXISTS spans_service_idx    ON spans (service, started_at DESC);

COMMENT ON TABLE spans IS
    'OTLP spans owned by the telemetry service, used to join audit decisions to distributed flows.';
