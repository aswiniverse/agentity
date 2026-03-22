CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    email TEXT,
    display_name TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(external_id, issuer)
);

CREATE TABLE IF NOT EXISTS user_agent_bindings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    agent_id TEXT NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    UNIQUE(user_id, agent_id)
);

CREATE TABLE IF NOT EXISTS oidc_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer_url TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    jwks_url TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
