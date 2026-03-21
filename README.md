# Agentity

> **The open-source Identity & Access Management layer built for the age of autonomous AI.**

---

## The Problem Nobody Is Talking About

It's 2 AM. An AI orchestrator spawns a research agent to gather competitive intelligence. That agent spawns a code agent to parse PDFs. The code agent decides it needs database access — so it asks for it. And gets it. Because nothing said no.

Nobody breached the system. There was no malware. The agents were just doing what they were told — by each other, without any cryptographic proof of who authorized what, with what scope, for how long.

This is the silent security crisis of the agentic era.

Human IAM — Keycloak, Auth0, Okta — was built for people who log in. It has no concept of an agent that spawns children, delegates capabilities, and runs autonomously for hours. When you drop a JWT into a multi-hop agent system, you get one of two outcomes: **everything is blocked** (you locked it down so tight nothing works) or **everything is permitted** (you opened it up so the agents could operate). There is no middle ground, because the primitives don't exist.

**Agentity is that middle ground.**

---

## The Story of a Safe Agentic System

Imagine you're building a research pipeline. An orchestrator receives a task: *"Analyze our competitors and draft a market report."*

Here's how it plays out with Agentity:

**Step 1 — Identity.** The orchestrator registers with Agentity. It gets a unique ID — `agent://orchestrator-uuid` — backed by an Ed25519 key pair. Its identity is cryptographically tied to what it *is*: its model (`claude-3-5-sonnet`), its system prompt hash, its allowed tools. Not who runs it. What it is.

**Step 2 — A root token is issued.** The Agentity server signs a root AgentCapability Token (ACT) granting: `[web_search, read_file, write_report]`, valid for 2 hours, delegatable up to 3 hops.

**Step 3 — The orchestrator spawns a research agent.** It signs a new delegation block *locally* — its private key never leaves the process — and appends it to the token. The child receives `[web_search]` only. Not `read_file`. Not `write_report`. The orchestrator gave less than it had, and that's the only direction the math allows.

**Step 4 — The research agent tries to get database access.** It fails. Not because of a firewall rule or an if-statement someone remembered to write. Because the token's cryptographic chain simply does not contain `db:read`. There's nothing to override. No admin account to compromise. The capability was never delegated.

**Step 5 — The task completes. The orchestrator is revoked.** One API call. Every child agent, every grandchild, every token in the tree — instantly invalid. The audit log, signed with the server's private key, shows exactly what happened, who authorized what, and when.

This is Agentity.

---

## What Makes It Different

### AgentCapability Tokens (ACT)

ACTs are the core primitive — and they're unlike anything in the existing IAM world.

A JWT is a single claims block. Anybody who holds it can use it. You can't see how it got there. You can't narrow it. You can only accept or reject it.

An ACT is a **chain of signed blocks**. Each block was signed by the agent that issued it. Each block can only *reduce* capabilities — never add them. The server verifies every signature in the chain, the intersection of every capability set, and every expiry condition before accepting a single request.

```
Server signs Block 0  →  orchestrator gets [web_search, code_exec, db:read]
Orchestrator signs Block 1  →  research-agent gets [web_search]
research-agent signs Block 2  →  sub-agent gets [web_search]

Effective caps at Block 2: intersection = [web_search]
Attempting to claim db:read at Block 2: cryptographic failure.
```

Capability amplification is not a policy violation. It's a mathematical impossibility.

### CEL Policy Engine — Runtime Enforcement

Beyond the token math, a Google CEL policy engine sits at every token issuance and verification call. Write policies in plain expressions that your team can actually read:

```
# Block delegation chains deeper than 3 hops
chain_depth <= 3

# Restrict old model versions from accessing production tools
agent_model != "gpt-3.5-turbo"

# Only allow research tools for read-only capabilities
"db:write" in capabilities ? agent_model in ["claude-3-5-sonnet"] : true
```

Policies are live — add, remove, and update them at runtime without a deployment.

### Zero-Trust Key Architecture

Every agent holds its own Ed25519 private key. Delegation signing happens **client-side**. The server never touches a private key after registration. If the server is compromised, the attacker gets public keys and audit logs — not the ability to forge delegation chains.

### MCP-Native

Agentity ships a `pkg/mcp` middleware that maps Model Context Protocol tool names to ACT capabilities. Drop it in front of any MCP server and every tool call becomes authenticated, audited, and capability-gated.

```go
capMap := mcp.NewToolCapabilityMap().
    Map("read_file", "read_file").
    Map("execute_code", "code_exec")

auth := mcp.NewMiddleware(delegationEngine, capMap)
http.Handle("/mcp/call", auth.Handler(yourMCPHandler))
```

---

## Get Running in 60 Seconds

### One Command (Docker)

```bash
docker compose up -d
```

Agentity starts with PostgreSQL, Redis, and a freshly generated root key. API at `http://localhost:8080`.

### No Dependencies (Dev Mode)

```bash
go run ./cmd/agentity --dev
```

In-memory store, auto-generated root key, admin key is `dev-admin-key`. Perfect for local development and CI.

### Build from Source

```bash
git clone https://github.com/agentity/agentity.git
cd agentity
make build
./bin/agentity --dev
```

---

## A Real Workflow

```bash
# Register your orchestrator agent
agentctl agents register \
  --name "Orchestrator" \
  --model "claude-3-5-sonnet-20241022" \
  --tools "web_search,code_exec,write_report"

# Issue a root token: 2 hours, max 3 delegation hops
agentctl tokens issue \
  --agent "agent://<uuid>" \
  --caps "web_search,code_exec,write_report" \
  --ttl 2h \
  --max-delegations 3

# Token is now live. Your orchestrator can delegate to children.
# Each child can only receive a SUBSET of the parent's capabilities.

# When done — revoke the orchestrator and everything it spawned
agentctl agents revoke <uuid> --cascade

# Full signed audit trail
agentctl audit list --limit 50
```

---

## Python SDK

```python
from agentity import AgentityClient
from agentity.crypto import delegate_token_locally
import time

client = AgentityClient(base_url="http://localhost:8080", api_key="dev-admin-key")

# Register the orchestrator
orchestrator, priv_key = client.register_agent(
    name="orchestrator",
    model="claude-3-5-sonnet-20241022",
    tools=["web_search", "code_exec", "write_report"],
)

# Issue a root token
token, token_id = client.issue_token(
    agent_id=orchestrator.id,
    capabilities=["web_search", "code_exec", "write_report"],
    expires_at=int(time.time()) + 7200,
    max_delegations=3,
)

# Register a child — it can only get a subset
researcher, _ = client.register_agent(
    name="research-agent",
    parent_id=orchestrator.id,
)

# Delegate locally — private key never leaves this process
child_token = delegate_token_locally(
    encoded_parent_token=token,
    child_agent_id=researcher.id,
    capabilities=["web_search"],       # subset only — code_exec is gone
    expires_at=int(time.time()) + 3600,
    parent_private_key_b64=priv_key,
)

# Submit for audit recording — server verifies every signature
client.submit_delegated_token(child_token)

# Verify at any tool boundary
verified = client.verify_token(child_token)
print(f"Agent: {verified.agent_id}")
print(f"Capabilities: {verified.capabilities}")  # ['web_search']
print(f"Chain depth: {verified.chain_depth}")    # 2
```

Install: `pip install agentity`

---

## Go SDK

```go
client := sdk.NewClient("http://localhost:8080", "dev-admin-key")

orch, orchKey, _ := client.RegisterAgent(ctx, sdk.RegisterAgentRequest{
    Name:  "Orchestrator",
    Model: "claude-3-5-sonnet-20241022",
    Tools: []string{"web_search", "code_exec"},
})

tok, _ := client.IssueToken(ctx, sdk.IssueTokenRequest{
    AgentID:      orch.ID,
    Capabilities: []string{"web_search", "code_exec"},
    Conditions:   token.BlockConditions{
        ExpiresAt:      time.Now().Add(2 * time.Hour).Unix(),
        MaxDelegations: 3,
    },
})

// Delegate — attenuation enforced at signing time
delegated, _ := client.DelegateToken(ctx, sdk.DelegateTokenRequest{
    ParentToken:    tok,
    ChildAgentID:   child.ID,
    Capabilities:   []string{"web_search"}, // code_exec not included
    Conditions:     token.BlockConditions{ExpiresAt: time.Now().Add(time.Hour).Unix()},
    ParentAgentKey: orchKey,
})

verified, _ := client.VerifyToken(ctx, delegated)
// verified.Capabilities == ["web_search"]
// verified.ChainDepth   == 2
```

---

## Observability Built In

| Signal | Endpoint | What You Get |
|---|---|---|
| **Prometheus metrics** | `GET /metrics` | Tokens issued/verified/rejected, policy denials, verification latency histograms |
| **Signed audit log** | `GET /api/v1/audit` | Every issuance, delegation, verification, and revocation — signed with the server's root key |
| **OpenAPI spec** | `GET /api/v1/openapi.json` | Full OpenAPI 3.1 — import into Postman, generate clients, or browse with `/docs` |

---

## CEL Policy Examples

```bash
# Deny delegation chains deeper than 2 hops
agentctl admin policies create \
  --name "shallow-chains-only" \
  --expr "chain_depth <= 2" \
  --action allow \
  --priority 100

# Block deprecated models from production tool access
agentctl admin policies create \
  --name "no-legacy-models" \
  --expr "agent_model != \"gpt-3.5-turbo\"" \
  --action allow \
  --priority 90

# Require explicit read capability for any file access
agentctl admin policies create \
  --name "require-read-for-files" \
  --expr "\"read_file\" in capabilities" \
  --action allow \
  --priority 50
```

---

## How Agentity Stacks Up

| | Agentity | Keycloak | Auth0 | Casdoor |
|---|---|---|---|---|
| Designed for AI agents | **Yes** | No | No | No |
| Cryptographic capability chains | **Yes** | No | No | No |
| Client-side delegation signing | **Yes** | No | No | No |
| Multi-hop trust chains | **Yes** | No | No | No |
| Capability attenuation (math-enforced) | **Yes** | No | No | No |
| Cascade revocation | **Yes** | Partial | No | No |
| CEL runtime policy engine | **Yes** | No | No | No |
| MCP gateway middleware | **Yes** | No | No | No |
| System prompt fingerprinting | **Yes** | No | No | No |
| Signed audit trail | **Yes** | Partial | Partial | Partial |
| OAuth2.1 / OIDC compatible | **Yes** | Yes | Yes | Yes |
| Prometheus metrics | **Yes** | Yes | Partial | No |
| Open source | **Yes** | Yes | No | Yes |

---

## Configuration

```bash
# Server
AGENTITY_SERVER_PORT=8080
AGENTITY_AUTH_ADMIN_API_KEY=your-secret-key

# Store
AGENTITY_STORE_TYPE=postgres           # or "memory"
AGENTITY_STORE_DSN=postgres://user:pass@host/db

# Revocation (Redis)
AGENTITY_REDIS_ENABLED=true
AGENTITY_REDIS_ADDR=localhost:6379

# OIDC
AGENTITY_OIDC_ISSUER_URL=https://agentity.yourdomain.com
```

All settings are also available as flags and in `config.yaml`. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full internals reference.

---

## Contributing

Agentity is open source and actively welcoming contributions.

```bash
git clone https://github.com/agentity/agentity.git
cd agentity
go mod download
make run-dev       # starts with --dev, hot reload

make test          # full test suite (unit + e2e)
make lint          # golangci-lint
make build         # compiles agentity + agentctl binaries
```

The project follows [Conventional Commits](https://www.conventionalcommits.org/). Every PR needs tests. Every feature needs a passing E2E.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the codebase map, internal package contracts, and design decisions.

---

## License

Apache 2.0. Use it, ship it, build on it.

---

*Agentity is maintained by the open-source community. If you're building multi-agent systems and want cryptographically sound IAM — this is the project.*
