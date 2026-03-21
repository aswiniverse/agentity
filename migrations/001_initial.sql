-- Agentity Initial Schema

CREATE TABLE IF NOT EXISTS agents (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    version         TEXT NOT NULL DEFAULT '',
    public_key      TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    system_prompt_hash TEXT NOT NULL DEFAULT '',
    tool_fingerprint   TEXT NOT NULL DEFAULT '',
    tools           JSONB NOT NULL DEFAULT '[]',
    model           TEXT NOT NULL DEFAULT '',
    parent_id       TEXT REFERENCES agents(id),
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_parent_id ON agents(parent_id);
CREATE INDEX idx_agents_key_id ON agents(key_id);
CREATE INDEX idx_agents_model ON agents(model);

CREATE TABLE IF NOT EXISTS tokens (
    id              TEXT PRIMARY KEY,
    token_data      JSONB NOT NULL,
    root_agent_id   TEXT NOT NULL REFERENCES agents(id),
    chain_depth     INT NOT NULL DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tokens_root_agent ON tokens(root_agent_id);
CREATE INDEX idx_tokens_status ON tokens(status);
CREATE INDEX idx_tokens_expires_at ON tokens(expires_at);

CREATE TABLE IF NOT EXISTS revocations (
    id              SERIAL PRIMARY KEY,
    token_id        TEXT,
    agent_id        TEXT,
    reason          TEXT NOT NULL DEFAULT '',
    cascade_flag    BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_revocations_token_id ON revocations(token_id);
CREATE INDEX idx_revocations_agent_id ON revocations(agent_id);

CREATE TABLE IF NOT EXISTS policies (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    expression      TEXT NOT NULL,
    priority        INT NOT NULL DEFAULT 0,
    action          TEXT NOT NULL DEFAULT 'allow' CHECK (action IN ('allow', 'deny')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_policies_priority ON policies(priority DESC);
