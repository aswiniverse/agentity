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

Policies are live — add, remove, and update them at runtime without a deployment. Policies are persisted to Postgres so they survive restarts.

### Zero-Trust Key Architecture

Every agent holds its own Ed25519 private key. Delegation signing happens **client-side**. The server never touches a private key after registration. If the server is compromised, the attacker gets public keys and audit logs — not the ability to forge delegation chains.

### System Prompt Fingerprinting

When an agent registers, Agentity records a hash of its system prompt and a fingerprint of its allowed tools. These are embedded in the root token block at issuance. At every verify call, Agentity checks the current agent fingerprint against what was baked into the token — if the system prompt changed, the token is rejected before it can be used.

```
Token issued with fingerprint A → agent's system prompt updated → verify → REJECTED
"agent fingerprint mismatch: system prompt changed"
```

Agents can't quietly swap their instructions mid-session.

### MCP-Native with OAuth 2.1

Agentity ships a `pkg/mcp` middleware that maps Model Context Protocol tool names to ACT capabilities. It implements OAuth 2.1 with PKCE and RFC 8707 resource indicators — drop it in front of any MCP server and every tool call becomes authenticated, audited, and capability-gated.

```go
capMap := mcp.NewToolCapabilityMap().
    Map("read_file", "read_file").
    Map("execute_code", "code_exec")

auth := mcp.NewMiddleware(delegationEngine, capMap)
http.Handle("/mcp/call", auth.Handler(yourMCPHandler))
```

Unauthorized calls receive a `WWW-Authenticate: Bearer realm="agentity", resource="..."` challenge per RFC 9728.

### Google A2A Bridge

Agentity ships a `pkg/a2a` middleware for the Google Agent-to-Agent protocol. Drop it in front of any A2A-compatible endpoint to get full ACT verification on every agent-to-agent skill call.

```go
bridge := a2a.NewMiddleware(delegationEngine, capabilityMap)
http.Handle("/a2a/", bridge.Handler(yourA2AHandler))
```

The middleware extracts `skill_id` and `task_id` from the JSON body, validates the ACT in the `Authorization` header, and maps skill IDs to required capabilities.

---

## Get Running in 60 Seconds

### One Command (Docker)

```bash
docker compose up -d
```

Agentity starts with PostgreSQL, Redis, and a freshly generated root key. API at `http://localhost:8080`. Admin UI at `http://localhost:8080/admin`.

### No Dependencies (Dev Mode)

```bash
go run ./cmd/agentity --dev
```

In-memory store, auto-generated root key, admin key is `dev-admin-key`. Perfect for local development and CI.

### Kubernetes (Helm)

```bash
helm install agentity charts/agentity \
  --set postgresql.enabled=true \
  --set ingress.enabled=true \
  --set ingress.host=agentity.yourdomain.com
```

The chart includes liveness/readiness probes, HPA, ConfigMap/Secret separation, and TLS ingress support. See `charts/agentity/values.yaml` for the full configuration reference.

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

# Issue a root token: 2 hours validity
agentctl tokens issue \
  --agent "agent://<uuid>" \
  --caps "web_search,code_exec,write_report" \
  --ttl 2h

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

### Framework Integrations

Agentity integrates natively with the major Python agent frameworks:

```python
# LangChain
from agentity.integrations.langchain import AuthenticatedChain
chain = AuthenticatedChain.from_llm(llm, token=token, required_capabilities=["read_file"])

# CrewAI
from agentity.integrations.crewai import AuthenticatedCrew
crew = AuthenticatedCrew(agents=[...], tasks=[...], token=token)

# AutoGen
from agentity.integrations.autogen import AuthenticatedAssistant
assistant = AuthenticatedAssistant(name="agent", token=token, required_capabilities=["code_exec"])
```

| Framework | Example |
|---|---|
| LangChain | [sdk/python/examples/langchain_example.py](sdk/python/examples/langchain_example.py) |
| CrewAI | [sdk/python/examples/crewai_example.py](sdk/python/examples/crewai_example.py) |
| AutoGen | [sdk/python/examples/autogen_example.py](sdk/python/examples/autogen_example.py) |

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
    Conditions: token.BlockConditions{
        ExpiresAt: time.Now().Add(2 * time.Hour).Unix(),
    },
})

// Delegate locally — private key never leaves the process
delegated, _ := client.DelegateTokenLocally(ctx,
    tok,                              // parent token
    child.ID,                         // child agent ID
    []string{"web_search"},           // attenuated capabilities
    token.BlockConditions{ExpiresAt: time.Now().Add(time.Hour).Unix()},
    orchKey,                          // parent private key (stays local)
)

verified, _ := client.VerifyToken(ctx, delegated)
// verified.Capabilities == ["web_search"]
// verified.ChainDepth   == 2
```

---

## User-to-Agent Binding (OIDC)

Link human identities to agents. When a user presents their OIDC `id_token` at token issuance, the user ID is embedded in the root token block and carried through the delegation chain.

```bash
# Register an OIDC provider
curl -X POST http://localhost:8080/api/v1/admin/oidc-providers \
  -H "Authorization: Bearer dev-admin-key" \
  -d '{"issuer": "https://accounts.google.com", "client_id": "my-app"}'

# Bind a user to an agent (user presents their OIDC id_token)
curl -X POST http://localhost:8080/api/v1/users/bind \
  -d '{"user_token": "<oidc-id-token>", "agent_id": "agent://uuid", "scopes": ["read_file"]}'

# Issue a token with user context
curl -X POST http://localhost:8080/api/v1/tokens/issue \
  -d '{"agent_id": "agent://uuid", "capabilities": ["read_file"], "user_token": "<oidc-id-token>", ...}'
```

The verified token carries `user_id` — audit logs tie every action to both the agent and the human who authorized it.

---

## Credential Vault

Per-agent encrypted credential storage. Store API keys, secrets, and connection strings — encrypted with AES-256-GCM, never returned in list operations.

```bash
# Store a credential
curl -X POST http://localhost:8080/api/v1/agents/<id>/credentials \
  -H "Authorization: Bearer dev-admin-key" \
  -d '{"key": "openai_api_key", "value": "sk-..."}'

# List credential keys (values never returned in list)
curl http://localhost:8080/api/v1/agents/<id>/credentials

# Retrieve a specific credential
curl http://localhost:8080/api/v1/agents/<id>/credentials/openai_api_key

# Delete a credential
curl -X DELETE http://localhost:8080/api/v1/agents/<id>/credentials/openai_api_key
```

Set `AGENTITY_VAULT_KEY` to a 32-byte hex string to enable the vault. Keys are versioned (`local-v1`) for future KMS rotation support.

---

## Human Approval Gates

Require human sign-off before an agent can access sensitive resources. Supports webhook notifications for async workflows.

```bash
# Request approval
curl -X POST http://localhost:8080/api/v1/approvals \
  -d '{"agent_id": "agent://uuid", "token_id": "tok-123", "resource": "prod-database", "reason": "Needs access to run migration", "webhook_url": "https://yourapp.com/hooks/approvals"}'

# Webhook receives: {approval_id, agent_id, resource, reason, approve_url, deny_url}

# Approve (or deny) via URL or API
curl -X POST http://localhost:8080/api/v1/approvals/<id>/approve \
  -d '{"approver_id": "alice@example.com"}'
```

Pending approvals are queryable: `GET /api/v1/approvals?agent_id=<id>&status=pending`

---

## Admin UI

A built-in web dashboard is served at `/admin`. No separate service needed — it's embedded in the binary.

```
http://localhost:8080/admin
```

The dashboard shows agents, tokens, audit log, policies, approvals, and vault keys. All backed by the same REST API — no privileged access beyond the admin API key.

---

## Observability Built In

| Signal | Endpoint | What You Get |
|---|---|---|
| **Prometheus metrics** | `GET /metrics` | Tokens issued/verified/rejected, policy denials, verification latency histograms |
| **Signed audit log** | `GET /api/v1/audit` | Every issuance, delegation, verification, and revocation — signed with the server's root key, persisted to Postgres |
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

Policies are persisted to Postgres and survive restarts. The engine defaults to **deny-all** if the policy store fails to load — fail closed, not open.

---

## How Agentity Stacks Up

| | Agentity | Keycloak | Auth0 | AWS AgentCore |
|---|---|---|---|---|
| Designed for AI agents | **Yes** | No | No | Yes |
| Cryptographic capability chains | **Yes** | No | No | No |
| Client-side delegation signing | **Yes** | No | No | No |
| Multi-hop trust chains | **Yes** | No | No | No |
| Capability attenuation (math-enforced) | **Yes** | No | No | No |
| Cascade revocation | **Yes** | Partial | No | No |
| CEL runtime policy engine | **Yes** | No | No | No |
| MCP gateway (OAuth 2.1 + PKCE) | **Yes** | No | No | No |
| Google A2A bridge middleware | **Yes** | No | No | No |
| System prompt fingerprinting | **Yes** | No | No | No |
| Per-agent credential vault | **Yes** | No | No | **Yes** |
| Human approval gates | **Yes** | No | No | **Yes** |
| User-to-agent binding (OIDC) | **Yes** | Yes | Yes | Partial |
| LangChain / CrewAI / AutoGen | **Yes** | No | No | Partial |
| Kubernetes Helm chart | **Yes** | Yes | No | No |
| Signed audit trail | **Yes** | Partial | Partial | Partial |
| Open source | **Yes** | Yes | No | No |

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

# OIDC (for user-to-agent binding)
AGENTITY_OIDC_ISSUER_URL=https://accounts.google.com

# Credential vault (32-byte hex key)
AGENTITY_VAULT_KEY=0000000000000000000000000000000000000000000000000000000000000000
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
