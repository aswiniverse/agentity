-- Agentity Audit Log Schema

CREATE TABLE IF NOT EXISTS audit_log (
    id              TEXT PRIMARY KEY,
    event_type      TEXT NOT NULL,
    actor_id        TEXT NOT NULL,
    target_id       TEXT NOT NULL,
    action          TEXT NOT NULL,
    token_id        TEXT,
    outcome         TEXT NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',
    metadata        JSONB NOT NULL DEFAULT '{}',
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    signature       TEXT NOT NULL
);

CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_log_actor_id ON audit_log(actor_id);
CREATE INDEX idx_audit_log_target_id ON audit_log(target_id);
CREATE INDEX idx_audit_log_token_id ON audit_log(token_id);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_log_outcome ON audit_log(outcome);
