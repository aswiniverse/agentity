CREATE TABLE IF NOT EXISTS credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id TEXT NOT NULL,
    key TEXT NOT NULL,
    encrypted_value BYTEA NOT NULL,
    iv BYTEA NOT NULL,
    key_version TEXT NOT NULL DEFAULT 'local-v1',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(agent_id, key)
);
CREATE INDEX IF NOT EXISTS idx_credentials_agent_id ON credentials(agent_id);
