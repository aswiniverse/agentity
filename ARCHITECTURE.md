# Agentity — Architecture Reference

This document is the internals reference for contributors and integrators. For the project overview, quickstart, and SDK examples, see [README.md](README.md).

---

## Table of Contents

1. [High-Level Architecture](#high-level-architecture)
2. [Package Map](#package-map)
3. [Core Primitive: AgentCapability Token (ACT)](#core-primitive-agentcapability-token-act)
4. [Request Lifecycle](#request-lifecycle)
5. [Internal Packages](#internal-packages)
   - [identity](#identity)
   - [delegation](#delegation)
   - [policy](#policy)
   - [revocation](#revocation)
   - [audit](#audit)
   - [metrics](#metrics)
   - [api](#api)
6. [Public Packages](#public-packages)
   - [pkg/token](#pkgtoken)
   - [pkg/crypto](#pkgcrypto)
   - [pkg/mcp](#pkgmcp)
   - [pkg/sdk](#pkgsdk)
7. [Storage Layer](#storage-layer)
8. [Configuration](#configuration)
9. [Middleware Stack](#middleware-stack)
10. [Security Properties](#security-properties)
11. [Design Decisions](#design-decisions)

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        HTTP API (:8080)                          │
│  chi router · RequestID · Logging · CORS · RateLimit · MaxBytes  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
   ┌─────────────┐  ┌────────────┐  ┌────────────────┐
   │  Identity   │  │   Token    │  │  Admin/Audit   │
   │  Handlers   │  │  Handlers  │  │   Handlers     │
   └──────┬──────┘  └─────┬──────┘  └───────┬────────┘
          │               │                  │
          ▼               ▼                  ▼
   ┌─────────────┐  ┌────────────────────────────────┐
   │  identity   │  │         policy.Engine          │
   │  .Service   │  │    (CEL — deny-first eval)     │
   └──────┬──────┘  └──────────────┬─────────────────┘
          │                        │
          ▼                        ▼
   ┌─────────────┐  ┌────────────────────────────────┐
   │   Store     │  │      delegation.Engine         │
   │ (mem/pgx)   │  │  ACT signing · verification    │
   └─────────────┘  └──────────────┬─────────────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
             ┌────────────┐              ┌──────────────┐
             │ revocation │              │  audit       │
             │ .Registry  │              │  .Logger     │
             │(mem/Redis) │              │(signed JSON) │
             └────────────┘              └──────────────┘
```

---

## Package Map

```
agentity/
├── cmd/
│   ├── agentity/        # Server binary entry point
│   └── agentctl/        # CLI management tool
│
├── internal/
│   ├── api/             # HTTP handlers, router, middleware
│   │   ├── router.go              chi router wiring
│   │   ├── middleware.go          auth, rate limiting, CORS, logging
│   │   ├── handlers_identity.go   agent CRUD
│   │   ├── handlers_token.go      issue / verify / delegate / revoke
│   │   ├── handlers_admin.go      policies, stats, revocations
│   │   ├── handlers_audit.go      audit log queries
│   │   ├── handlers_oauth.go      OAuth2.1 token + introspect + revoke
│   │   ├── handlers_oidc.go       OIDC discovery + JWKS + userinfo
│   │   └── handlers_openapi.go    OpenAPI 3.1 spec + Swagger redirect
│   │
│   ├── identity/        # Agent identity management
│   │   ├── service.go             RegisterAgent, GetAgent, RevokeAgent (BFS cascade)
│   │   └── types.go               Agent, AgentStatus, RegisterAgentRequest
│   │
│   ├── delegation/      # ACT issuance and verification
│   │   ├── engine.go              IssueToken, VerifyToken, SubmitDelegated, RevokeToken
│   │   └── verifier.go            KeyResolver with LRU cache (cap 10,000)
│   │
│   ├── policy/          # CEL runtime policy engine
│   │   └── engine.go              AddPolicy, RemovePolicy, Evaluate (deny-first)
│   │
│   ├── revocation/      # Token revocation registry
│   │   └── registry.go            in-memory + Redis backends
│   │
│   ├── audit/           # Immutable signed audit log
│   │   └── logger.go              append-only, Ed25519-signed entries
│   │
│   ├── metrics/         # Prometheus instrumentation
│   │   └── metrics.go             counters + histograms via promauto
│   │
│   ├── store/           # Storage interface + implementations
│   │   ├── memory.go              in-process (dev, tests)
│   │   └── postgres.go            pgx/v5 production backend
│   │
│   ├── server/          # HTTP server lifecycle (start, graceful shutdown)
│   │   └── server.go
│   │
│   └── config/          # Configuration loading (viper)
│       └── config.go
│
├── pkg/
│   ├── token/           # ACT data structures and signing logic
│   │   ├── act.go                 ACT, Block, encode/decode
│   │   ├── claims.go              BlockConditions (exp, max_delegations)
│   │   └── verify.go              multi-block signature verification
│   │
│   ├── crypto/          # Ed25519 key management
│   │   ├── keys.go                RootKeyStore, generate, load, sign
│   │   └── hash.go                SHA-256 fingerprinting utilities
│   │
│   ├── mcp/             # Model Context Protocol auth middleware
│   │   └── mcp.go                 ToolCapabilityMap, Middleware, VerifyToolCall
│   │
│   └── sdk/             # Go client SDK
│       └── client.go              typed API wrapper
│
├── sdk/
│   └── python/          # Python client SDK (pip install agentity)
│       └── agentity/
│           ├── client.py          AgentityClient, AsyncAgentityClient
│           ├── crypto.py          delegate_token_locally, generate_key_pair
│           └── models.py          Agent, ACT, VerifiedACT dataclasses
│
├── test/
│   └── e2e/             # End-to-end test suite (httptest.NewServer)
│
└── migrations/          # PostgreSQL schema migrations
```

---

## Core Primitive: AgentCapability Token (ACT)

An ACT is a **chain of signed JSON blocks**, not a single claims payload. Each block was signed by a different agent's Ed25519 private key. The server verifies the entire chain on every request.

### Block Structure

```json
{
  "block_index": 0,
  "issuer_id":   "server",
  "agent_id":    "agent://550e8400-...",
  "key_id":      "sha256:abc123...",
  "capabilities": ["web_search", "code_exec", "db:read"],
  "conditions": {
    "exp": 1748000000,
    "max_delegations": 3
  },
  "signature": "<ed25519-sig-over-canonical-json>"
}
```

### Delegation (Attenuation)

When an agent delegates to a child, it appends a new block signed with its own private key. The new block:

- **May only reduce** capabilities — the intersection of parent and child sets is taken
- **May not extend** the expiry beyond the parent block's expiry
- **Decrements** the remaining delegation count

```
Block 0 (server key):     caps=[web_search, code_exec, db:read], max_del=3
Block 1 (orchestrator):   caps=[web_search, code_exec],          max_del=2
Block 2 (research-agent): caps=[web_search],                     max_del=1

Effective capabilities = intersection of all blocks = [web_search]
```

Capability amplification is a **mathematical impossibility**, not a policy check.

### Wire Format

An ACT is JSON-encoded, then base64url (no padding) for transport:

```
base64url(json({"blocks": [...]}))
```

All signing uses canonical JSON (keys sorted, no extra whitespace) to ensure byte-exact reproducibility across implementations.

---

## Request Lifecycle

### Token Issuance (`POST /api/v1/tokens/issue`)

```
1. AdminAuthMiddleware      — verify X-Admin-Key header
2. AgentRateLimiter         — per-agent bucket (20 req/sec)
3. handlers_token.IssueToken
   ├── identity.GetAgent    — verify agent exists and is active
   ├── policy.Evaluate      — run CEL policies (deny-first)
   │     returns 403 + problem-details if denied
   ├── delegation.IssueToken — sign Block 0 with root key
   ├── audit.Log            — append signed audit entry
   └── metrics.TokensIssued.Inc()
```

### Token Verification (`POST /api/v1/tokens/verify`)

```
1. AdminAuthMiddleware
2. handlers_token.VerifyToken
   ├── delegation.VerifyToken
   │   ├── pkg/token.Verify  — check every block's Ed25519 signature
   │   ├── KeyResolver       — look up public key (LRU cache → store)
   │   ├── check expiry      — all blocks must not be expired
   │   └── revocation check  — token ID must not be in registry
   ├── policy.Evaluate       — policies applied post-verify too
   │     returns 403 if denied
   ├── metrics.TokensVerified / VerificationDuration
   └── return effective capabilities + chain depth
```

### Client-Side Delegation (`POST /api/v1/tokens/delegate`)

```
Client side (never sent over wire):
  parent_private_key → sign new block → new ACT bytes

Server side (SubmitDelegatedToken):
1. delegation.VerifyToken   — full chain verification
2. audit.Log               — record delegation event
3. return chain metadata
```

---

## Internal Packages

### identity

**File:** `internal/identity/service.go`

The identity service owns the agent registry. Each agent has:
- A UUID (`agent://uuid`)
- An Ed25519 public key (registered at creation)
- A `Status`: `active | suspended | revoked`
- An optional `ParentID` forming a delegation tree

**Cascade revocation** uses iterative BFS (not recursion) to prevent stack overflow on deep trees:

```go
// Queue-based BFS — safe for trees 100+ levels deep
type item struct{ id string; depth int }
queue := []item{{id, 0}}
for len(queue) > 0 {
    cur := queue[0]; queue = queue[1:]
    if cur.depth > maxRevokeDepth { return errDepthExceeded }
    children := store.GetChildren(cur.id)
    for _, child := range children {
        queue = append(queue, item{child.ID, cur.depth + 1})
    }
}
```

### delegation

**File:** `internal/delegation/engine.go`, `verifier.go`

The delegation engine handles:
- **IssueToken**: signs Block 0 with the server's root Ed25519 key
- **VerifyToken**: verifies every block in the chain
- **SubmitDelegatedToken**: accepts a client-signed chain, re-verifies it, logs it
- **RevokeToken**: adds token ID to the revocation registry

The **KeyResolver** provides public keys during verification. It maintains an **LRU cache** (max 10,000 entries) backed by `container/list` to prevent repeated store hits:

```
Lookup(keyID):
  1. Check LRU cache (O(1), mutex-protected)
  2. On miss: query store, insert into LRU front
  3. If LRU at capacity: evict LRU tail
  InvalidateCache(keyID): remove from cache + list
```

### policy

**File:** `internal/policy/engine.go`

The CEL engine evaluates policies in priority order (highest first), with deny policies evaluated before allow policies.

**Evaluation logic:**
```
if any DENY policy matches → return false
if any ALLOW policy matches → return true
if ALLOW policies exist but none matched → return false
if NO policies exist → return true (default allow)
```

**Available CEL variables:**

| Variable | Type | Description |
|---|---|---|
| `agent_id` | string | Agent UUID |
| `agent_model` | string | Model identifier |
| `chain_depth` | int | Number of delegation blocks |
| `capabilities` | list(string) | Effective capabilities |
| `resource` | string | Target resource (if set) |
| `action` | string | Requested action (if set) |
| `expires_at` | int | Unix timestamp of expiry |

Policies are live — `AddPolicy` and `RemovePolicy` take effect immediately, no restart needed.

### revocation

**File:** `internal/revocation/registry.go`

The revocation registry supports two backends selected at startup:

| Backend | Use case | Durability |
|---|---|---|
| In-memory | Dev, tests | Process lifetime |
| Redis | Production | Persistent, shared across replicas |

When an agent is revoked with `--cascade`, the identity service revokes the agent tree. Each agent's tokens are invalidated by adding the agent ID to the registry — any token issued by or for that agent fails verification.

### audit

**File:** `internal/audit/logger.go`

Every significant event (issuance, verification, delegation, revocation) is written as an audit entry signed with the server's Ed25519 root key. This means:

- Audit logs cannot be silently tampered with
- Every entry can be independently verified
- The trail is queryable via `GET /api/v1/audit`

### metrics

**File:** `internal/metrics/metrics.go`

All metrics are registered via `promauto` (auto-registers with the default Prometheus registry) and exposed at `GET /metrics` via `promhttp.Handler()`.

| Metric | Type | Description |
|---|---|---|
| `agentity_tokens_issued_total` | Counter | Tokens issued |
| `agentity_tokens_verified_total` | Counter | Successful verifications |
| `agentity_tokens_rejected_total` | Counter | Failed verifications |
| `agentity_tokens_delegated_total` | Counter | Delegations submitted |
| `agentity_tokens_revoked_total` | Counter | Tokens revoked |
| `agentity_agents_registered_total` | Counter | Agents registered |
| `agentity_policy_denials_total` | Counter | CEL policy denials |
| `agentity_token_verification_duration_seconds` | Histogram | Verification latency |
| `agentity_token_issuance_duration_seconds` | Histogram | Issuance latency |

### api

**File:** `internal/api/`

The API layer uses [chi](https://github.com/go-chi/chi) for routing. All routes follow REST conventions. Error responses use [RFC 7807 Problem Details](https://www.rfc-editor.org/rfc/rfc7807):

```json
{
  "type":   "https://agentity.dev/errors/policy-denied",
  "title":  "Policy Denied",
  "status": 403,
  "detail": "policy 'deny-legacy-models' rejected this request"
}
```

**Defined problem types:**

| Type | Status | Trigger |
|---|---|---|
| `policy-denied` | 403 | CEL policy matched |
| `rate-limited` | 429 | Per-agent bucket exceeded |
| `agent-not-found` | 404 | Unknown agent ID |
| `token-expired` | 401 | ACT past expiry |
| `token-revoked` | 401 | Token in revocation registry |
| `invalid-token` | 400 | Malformed ACT or bad signature |

---

## Public Packages

### pkg/token

Implements the ACT data structure and signing protocol. Key types:

```go
type ACT struct {
    Blocks []Block `json:"blocks"`
}

type Block struct {
    BlockIndex   int             `json:"block_index"`
    IssuerID     string          `json:"issuer_id"`
    AgentID      string          `json:"agent_id"`
    KeyID        string          `json:"key_id"`
    Capabilities []string        `json:"capabilities"`
    Conditions   BlockConditions `json:"conditions"`
    Signature    string          `json:"signature"`
}

type BlockConditions struct {
    ExpiresAt      int64 `json:"exp"`
    MaxDelegations int   `json:"max_delegations,omitempty"`
}
```

Signing is over canonical JSON (sorted keys, compact encoding) of the block with `Signature` set to `""`. This ensures byte-exact reproducibility across Go and Python implementations.

### pkg/crypto

Manages Ed25519 key pairs:

- **RootKeyStore**: holds the server's root key pair; auto-generates on first start
- **compute_key_id**: SHA-256 of the public key bytes, base64url-encoded, used as the `kid` field in JWKS and ACT blocks
- Used by both the server (root key signing) and agents (per-agent key pairs)

### pkg/mcp

The MCP auth middleware maps Model Context Protocol tool names to ACT capabilities and enforces them at the HTTP boundary:

```go
capMap := mcp.NewToolCapabilityMap().
    Map("read_file", "read_file").       // tool name → required capability
    Map("execute_code", "code_exec")

auth := mcp.NewMiddleware(delegationEngine, capMap)
http.Handle("/mcp/call", auth.Handler(yourMCPHandler))
```

The middleware:
1. Extracts the ACT from `Authorization: Bearer <token>` or JSON body `"token"` field
2. Extracts the tool name from `X-MCP-Tool` header or JSON body `"tool"` field
3. Calls `VerifyToolCall` which verifies the ACT and checks the required capability
4. Stores `AuthResult{AgentID, Capabilities, ChainDepth, TokenID}` in the request context
5. Returns `401` if the token is invalid or the capability is missing, `400` if the tool name is absent

Retrieve auth info downstream:
```go
result := mcp.AuthResultFromContext(r.Context())
// result.AgentID, result.Capabilities, result.ChainDepth
```

### pkg/sdk

The Go client SDK wraps the HTTP API with typed request/response structs. It is used internally by `agentctl` and is importable by Go applications:

```go
client := sdk.NewClient("http://localhost:8080", "dev-admin-key")
agent, key, err := client.RegisterAgent(ctx, sdk.RegisterAgentRequest{...})
token, err       := client.IssueToken(ctx, sdk.IssueTokenRequest{...})
verified, err    := client.VerifyToken(ctx, encodedToken)
```

---

## Storage Layer

The `Store` interface abstracts all persistence. Both implementations satisfy the same interface, making it easy to swap without changing business logic.

```go
type Store interface {
    // Agents
    CreateAgent(a Agent) error
    GetAgent(id string) (*Agent, error)
    UpdateAgent(a Agent) error
    ListAgents(offset, limit int) ([]Agent, error)
    GetChildren(parentID string) ([]Agent, error)

    // Tokens
    CreateToken(t Token) error
    GetToken(id string) (*Token, error)
    ListTokens(agentID string) ([]Token, error)

    // Audit
    AppendAuditEntry(e AuditEntry) error
    ListAuditEntries(offset, limit int) ([]AuditEntry, error)
}
```

**Memory store** (`internal/store/memory.go`): goroutine-safe maps with `sync.RWMutex`. Used in dev mode and all E2E tests via `httptest.NewServer`.

**PostgreSQL store** (`internal/store/postgres.go`): `pgx/v5` connection pool. Schema managed by SQL migrations in `migrations/`. Connection pool size defaults to 20 (`store.max_conns`).

---

## Configuration

Configuration is loaded in priority order: **flags > environment variables > config file > defaults**.

```
AGENTITY_SERVER_PORT       int     (default: 8080)
AGENTITY_SERVER_HOST       string  (default: 0.0.0.0)
AGENTITY_AUTH_ADMIN_API_KEY string (required in production)

AGENTITY_STORE_TYPE        string  "memory" | "postgres" (default: memory)
AGENTITY_STORE_DSN         string  postgres://user:pass@host/db

AGENTITY_REDIS_ENABLED     bool    (default: false)
AGENTITY_REDIS_ADDR        string  (default: localhost:6379)

AGENTITY_CRYPTO_ROOT_KEY_FILE string  path to PEM key file (auto-generated if absent)

AGENTITY_LOG_LEVEL         string  debug | info | warn | error
AGENTITY_LOG_FORMAT        string  json | console

AGENTITY_OIDC_ISSUER_URL   string  https://agentity.yourdomain.com
```

All keys follow the `AGENTITY_<SECTION>_<KEY>` pattern. In `config.yaml`, use nested keys: `server.port`, `store.dsn`, etc.

---

## Middleware Stack

Every request passes through this stack in order:

```
chi.Recoverer           panic recovery → 500
chi.RealIP              extract client IP from X-Real-IP / X-Forwarded-For
RequestIDMiddleware     generate/propagate X-Request-ID
LoggingMiddleware       zerolog structured request logging
CORSMiddleware          preflight handling + Access-Control headers
MaxBytesMiddleware      reject bodies > 1 MB
RateLimiter             100 req/sec per IP (token bucket)
AdminAuthMiddleware     X-Admin-Key header check (on /api/v1/*)
AgentRateLimiter        20 req/sec per agent ID (on issue + verify)
```

The **RateLimiter** (IP-based) and **AgentRateLimiter** (agent-ID-based) are separate token-bucket implementations. Each maintains a per-key bucket with a cleanup goroutine that evicts stale buckets every `5 * interval` to prevent unbounded memory growth.

---

## Security Properties

| Property | Mechanism |
|---|---|
| Capability attenuation | Mathematical: intersection computed in `pkg/token.Verify` |
| Forgery prevention | Ed25519 signature over canonical JSON on every block |
| Server key compromise | Attacker gets public keys only; cannot forge delegation chains |
| Cascade revocation | BFS through agent tree; each agent's token ID added to registry |
| Replay prevention | Token IDs checked against revocation registry on every verify |
| Runtime policy control | CEL engine evaluated at issuance and verification |
| Audit integrity | Every entry signed with root key; tampering is detectable |
| Depth amplification | `max_delegations` decremented at each hop; enforced cryptographically |

---

## Design Decisions

**Why Ed25519?** Fast, small keys (32 bytes public), constant-time verification, no parameter selection errors (unlike ECDSA), well-supported in Go stdlib and the Python `cryptography` package.

**Why canonical JSON instead of a binary format?** Debuggability. A developer can base64-decode a token and read it. The performance cost is negligible compared to Ed25519 signing/verification.

**Why client-side delegation signing?** The server never sees private keys after registration. If the Agentity server is compromised, the attacker cannot forge delegation chains for any previously registered agent.

**Why CEL?** Google's Common Expression Language compiles to bytecode, is sandboxed (no I/O, no loops), and produces human-readable expressions. It gives operators expressive runtime control without deploying code.

**Why iterative BFS for cascade revocation?** A recursive approach with 1,000 nested agents would stack-overflow. Iterative BFS is O(n) in memory and bounded by `maxRevokeDepth = 100`.

**Why an LRU cache in the key resolver?** Each `VerifyToken` call resolves one key per block. Without caching, a 3-hop delegation chain hits the store 3 times. The LRU cap (10,000 entries) prevents unbounded growth while covering all active agents in a typical deployment.

**Why `httptest.NewServer` for E2E tests?** No external dependencies (no Docker, no ports). The full service stack — router, handlers, identity service, delegation engine, policy engine, metrics — spins up inside each test function with an in-memory store. Tests are hermetic, parallelizable, and run with `go test ./...`.

**Why `pkg/mcp` as a separate package?** MCP middleware is an optional integration. Keeping it in `pkg/` (rather than `internal/`) means external consumers can import it without pulling in all of Agentity's internal packages. It only depends on `pkg/token` and the `delegation.Engine` interface.
