# Agentity

**The first purpose-built, open-source Identity & Access Management system for AI agents.**

Think "Keycloak for agentic AI" -- Agentity provides cryptographic identity, capability-based delegation, and real-time revocation for multi-agent systems.

## Why Agentity?

As AI agents become autonomous actors -- browsing the web, executing code, calling APIs -- traditional IAM systems designed for human users fall short. Agents need:

- **Cryptographic identity** tied to what they are (model, tools, system prompt), not who operates them
- **Capability delegation** that can only attenuate, never amplify -- enforced cryptographically
- **Multi-hop trust chains** so an orchestrator can delegate to sub-agents with verifiable, scoped permissions
- **Instant revocation** that cascades through the entire delegation tree
- **Audit trails** with signed, non-repudiable execution receipts

Agentity solves all of these with a single, standards-compliant server.

## Core Innovation: AgentCapability Token (ACT)

Unlike JWTs (single claims block), ACT tokens contain a **chain of cryptographically signed blocks**. Each block in the chain can only **reduce** capabilities -- never add them. This is enforced at the cryptographic level.

```
ACT Token
+------------------------------------------+
| Block 0 (Root - signed by Agentity)      |
| Subject: agent://orchestrator            |
| Caps: [tool:web_search, tool:code_exec,  |
|        resource:db:read, resource:db:write]|
| Exp: 2025-01-01T00:00:00Z               |
| MaxDelegations: 3                        |
+------------------------------------------+
           |
           v  (attenuation - caps can only shrink)
+------------------------------------------+
| Block 1 (signed by orchestrator)         |
| Subject: agent://research-agent          |
| Caps: [tool:web_search]  <-- subset     |
| Exp: 2025-01-01T00:00:00Z  <-- <= parent|
| MaxDelegations: 1                        |
+------------------------------------------+
```

## Quick Start

### Docker (one command)

```bash
docker compose up -d
```

This starts Agentity with PostgreSQL and Redis. The API is available at `http://localhost:8080`.

### Dev Mode (no dependencies)

```bash
go run ./cmd/agentity --dev
```

This starts Agentity with an in-memory store, auto-generated root key, and the admin key set to `dev-admin-key`.

### Build from Source

```bash
make build
./bin/agentity --dev
```

## Architecture

```
+-------------------+     +-------------------+     +-------------------+
|   Agent / Client  |     |   Agent / Client  |     |   Agent / Client  |
+--------+----------+     +--------+----------+     +--------+----------+
         |                         |                         |
         +------------+------------+------------+------------+
                      |                         |
              +-------v-------+         +-------v-------+
              |  REST API     |         |  OAuth2/OIDC  |
              |  /api/v1/*    |         |  /oauth/*     |
              +-------+-------+         +-------+-------+
                      |                         |
              +-------v-------------------------v-------+
              |           API Router (Chi)              |
              |  Middleware: Auth, Logging, CORS, Rate  |
              +-------+--------------------------------+
                      |
         +------------+------------+
         |            |            |
+--------v--+ +------v-----+ +---v----------+
| Identity  | | Delegation | | Policy       |
| Service   | | Engine     | | Engine (CEL) |
+--------+--+ +------+-----+ +---+----------+
         |            |            |
+--------v------------v------------v--------+
|              Revocation Registry          |
|          (Redis + In-Memory fallback)     |
+-------------------------------------------+
         |
+--------v----------------------------------+
|              Audit Logger                 |
|        (Signed, non-repudiable)           |
+-------------------------------------------+
         |
+--------v----------------------------------+
|     Store (PostgreSQL / In-Memory)        |
+-------------------------------------------+
```

## API Reference

### Agent Management

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/agents` | Register a new agent |
| `GET` | `/api/v1/agents` | List agents (paginated) |
| `GET` | `/api/v1/agents/:id` | Get agent details |
| `GET` | `/api/v1/agents/:id/tree` | Get delegation tree |
| `POST` | `/api/v1/agents/:id/suspend` | Suspend an agent |
| `POST` | `/api/v1/agents/:id/revoke` | Revoke an agent |
| `POST` | `/api/v1/agents/:id/rotate-key` | Rotate signing key |

### Token Operations

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/tokens/issue` | Issue root token |
| `POST` | `/api/v1/tokens/delegate` | Delegate token to child |
| `POST` | `/api/v1/tokens/verify` | Verify a token |
| `POST` | `/api/v1/tokens/revoke` | Revoke a token |
| `GET` | `/api/v1/tokens/:id/chain` | Get delegation chain |

### OAuth2.1 / OIDC

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/oauth/token` | Token exchange (RFC 8693) |
| `POST` | `/oauth/introspect` | Token introspection (RFC 7662) |
| `POST` | `/oauth/revoke` | Token revocation (RFC 7009) |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery |
| `GET` | `/.well-known/jwks.json` | JWK Set |
| `GET` | `/oidc/userinfo` | Agent info |

### Admin

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/admin/stats` | System statistics |
| `GET` | `/api/v1/admin/policies` | List policies |
| `POST` | `/api/v1/admin/policies` | Create policy |
| `DELETE` | `/api/v1/admin/policies/:id` | Delete policy |
| `GET` | `/api/v1/admin/revocations` | List revocations |
| `GET` | `/api/v1/audit` | Query audit log |

### Error Format

All errors use RFC 7807 Problem Details:

```json
{
  "type": "https://agentity.dev/errors/capability-amplification",
  "title": "Capability Amplification Denied",
  "status": 403,
  "detail": "Capability 'tool:code_exec' not in parent effective capabilities"
}
```

## CLI Usage

```bash
# Register an agent
agentctl agents register --name "Orchestrator" --model claude-opus-4-5 --tools "web_search,code_exec"

# List agents
agentctl agents list

# Get agent details
agentctl agents get <agent-uuid>

# Issue a token
agentctl tokens issue --agent "agent://<uuid>" --caps "tool:web_search,tool:code_exec" --ttl 1h

# Verify a token
agentctl tokens verify <encoded-token>

# Revoke a token
agentctl tokens revoke <token-id> --reason "compromised"

# Revoke an agent (with cascade)
agentctl agents revoke <agent-uuid> --cascade

# View system stats
agentctl admin stats

# Create a policy
agentctl admin policies create --name "model-check" --expr "agent_model == 'claude-opus-4-5'" --action allow

# List policies
agentctl admin policies list
```

## Go SDK

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/agentity/agentity/pkg/sdk"
    "github.com/agentity/agentity/pkg/token"
)

func main() {
    client := sdk.NewClient("http://localhost:8080", "dev-admin-key")
    ctx := context.Background()

    // Register an orchestrator agent
    orch, orchKey, _ := client.RegisterAgent(ctx, sdk.RegisterAgentRequest{
        Name:  "Orchestrator",
        Model: "claude-opus-4-5",
        Tools: []string{"web_search", "code_exec"},
    })

    // Issue a root token
    tok, _ := client.IssueToken(ctx, sdk.IssueTokenRequest{
        AgentID:      orch.ID,
        Capabilities: []string{"tool:web_search", "tool:code_exec"},
        Conditions: token.BlockConditions{
            ExpiresAt:      time.Now().Add(time.Hour).Unix(),
            MaxDelegations: 3,
        },
    })

    // Register a child agent
    child, _, _ := client.RegisterAgent(ctx, sdk.RegisterAgentRequest{
        Name:     "Research Agent",
        Model:    "claude-opus-4-5",
        Tools:    []string{"web_search"},
        ParentID: orch.ID,
    })

    // Delegate with attenuated capabilities
    delegated, _ := client.DelegateToken(ctx, sdk.DelegateTokenRequest{
        ParentToken:    tok,
        ChildAgentID:   child.ID,
        Capabilities:   []string{"tool:web_search"}, // subset only
        Conditions:     token.BlockConditions{
            ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
        },
        ParentAgentKey: orchKey,
    })

    // Verify the delegated token
    verified, _ := client.VerifyToken(ctx, delegated)
    fmt.Printf("Agent: %s, Caps: %v, Depth: %d\n",
        verified.AgentID, verified.Capabilities, verified.ChainDepth)
}
```

## Core Concepts

### Agent Identity

Every agent registered with Agentity gets:
- A unique ID (`agent://<uuid>`)
- An Ed25519 key pair for signing
- A fingerprint derived from its system prompt hash, tool fingerprint, and model

### Capability-Based Delegation

Capabilities follow a `type:resource` pattern:
- `tool:web_search` -- permission to use web search
- `tool:code_exec` -- permission to execute code
- `resource:db:read` -- permission to read from a database
- `resource:db:write` -- permission to write to a database

When delegating, you can only grant a **subset** of your own capabilities. Attempting to add capabilities that the parent does not have results in a cryptographic error.

### Delegation Chains

Tokens can be delegated multiple times, forming a chain:
```
Server -> Orchestrator -> Research Agent -> Sub-Agent
```
Each hop adds a new block to the ACT token. The effective capabilities are the **intersection** of all blocks in the chain.

### Revocation

Revoking a token or agent immediately invalidates it. When revoking an agent with `cascade=true`, all child agents and their tokens are also revoked.

### Policy Engine

CEL-based policies provide fine-grained access control:
```
# Only allow specific models
agent_model == "claude-opus-4-5"

# Limit delegation depth
chain_depth <= 3

# Require specific capabilities
capabilities.exists(c, c == "tool:web_search")
```

## Comparison

| Feature | Agentity | Keycloak | Casdoor |
|---------|----------|----------|---------|
| Agent-native identity | Yes | No | No |
| Capability delegation chains | Yes | No | No |
| Cryptographic attenuation | Yes | No | No |
| Multi-hop delegation | Yes | No | No |
| System prompt fingerprinting | Yes | No | No |
| Cascade revocation | Yes | Partial | No |
| CEL policy engine | Yes | No | No |
| OAuth2.1/OIDC compatible | Yes | Yes | Yes |
| MCP gateway ready | Yes | No | No |
| Signed audit trail | Yes | Partial | Partial |

## Configuration

Agentity is configured via file, environment variables, or flags.

Environment variables use the prefix `AGENTITY_` with underscores replacing dots:
- `AGENTITY_SERVER_PORT=8080`
- `AGENTITY_STORE_TYPE=postgres`
- `AGENTITY_STORE_DSN=postgres://...`
- `AGENTITY_REDIS_ENABLED=true`
- `AGENTITY_AUTH_ADMIN_API_KEY=your-secret-key`

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`make test`)
5. Ensure code passes linting (`make lint`)
6. Commit your changes with a clear message
7. Push to the branch
8. Open a Pull Request

### Development Setup

```bash
# Clone the repo
git clone https://github.com/agentity/agentity.git
cd agentity

# Install dependencies
go mod download

# Run in dev mode
make run-dev

# Run tests
make test

# Build binaries
make build
```

## License

Apache 2.0
