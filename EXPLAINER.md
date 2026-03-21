# Agentity Explained — From Simple to Source Code

This document walks through the project at three levels:

1. **Plain English** — the problem and solution, no jargon
2. **Mid-level** — how the pieces fit together
3. **File-by-file** — what every file does and why it exists

---

## Level 1 — Plain English

### The Problem

Imagine you build an AI system with multiple agents. One agent is the "boss" (orchestrator). It spawns helper agents — a researcher, a coder, a writer. The boss has permission to read the database, search the web, write files.

Now the researcher agent decides it needs database access. So it asks for it. Nobody stops it. The database says yes.

**Nobody did anything wrong. The agent just... got access it shouldn't have.**

This is the problem. The tools we use for human login systems (like Keycloak, Auth0, Okta) don't understand agents. They don't know what "an agent spawned a child agent" means. So when people drop AI agents into these systems they either lock everything down so tight nothing works, or open it up so the agents can function. There's no middle ground.

### The Solution

Agentity gives every agent a **pass** — like a VIP wristband at a concert. But here's the twist: when the boss agent gives a wristband to a child agent, the child can only get a **smaller wristband**. It can never get more access than the boss had. Ever. It's not a rule someone checks. It's how the math works.

- Boss has: `[web_search, read_file, write_file, db:read]`
- Boss gives researcher: `[web_search, read_file]` only
- Researcher tries to claim `db:read` → **mathematically impossible**, not just "forbidden"

On top of that:
- Every "wristband" is cryptographically signed — you can't fake one
- When the boss is done, one command kills every wristband in the entire tree instantly
- A policy engine lets you add rules in plain English (`chain_depth <= 3`, `agent_model != "gpt-3.5"`)
- Every single action is logged and signed so you know exactly who did what

---

## Level 2 — How the Pieces Fit Together

### The Token (ACT — AgentCapability Token)

The core unit is the **ACT**. It is not like a normal login token (JWT). Instead of a single blob of claims, an ACT is a **chain of blocks** — like a chain of signed notes passed between agents.

```
Block 0 (signed by server):       agent=orchestrator, caps=[web_search, db:read]
Block 1 (signed by orchestrator):  agent=researcher,   caps=[web_search]
Block 2 (signed by researcher):    agent=sub-agent,    caps=[web_search]

What does the sub-agent actually have? → intersection = [web_search]
Can sub-agent claim db:read? → No. It's not in ANY block. The math says no.
```

Every block is signed by the **private key** of whoever issued it. The server checks every signature on every request. You can't fake a block because you don't have the right private key.

### The Five Core Systems

```
┌──────────────────────────────────────────────────────┐
│                   HTTP API (port 8080)               │
│     All requests come in here. Auth checked first.   │
└─────────────────────────┬────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
  ┌──────────┐    ┌──────────────┐   ┌────────────┐
  │ Identity │    │  Delegation  │   │   Policy   │
  │ Service  │    │   Engine     │   │   Engine   │
  │          │    │              │   │            │
  │ Who is   │    │ Issues and   │   │ CEL rules  │
  │ this     │    │ verifies ACT │   │ deny/allow │
  │ agent?   │    │ tokens       │   │ at runtime │
  └────┬─────┘    └──────┬───────┘   └────────────┘
       │                 │
       ▼                 ▼
  ┌──────────┐    ┌──────────────┐
  │  Store   │    │  Revocation  │
  │          │    │  Registry    │
  │ Postgres │    │              │
  │ or       │    │ Killed tokens│
  │ Memory   │    │ (Redis/mem)  │
  └──────────┘    └──────────────┘
```

**1. Identity Service** — knows about agents. When you register an agent, it gets a UUID and a fresh Ed25519 key pair. It stores: who this agent is, what tools it uses, its parent agent, and whether it's active/suspended/revoked.

**2. Delegation Engine** — the heart of the system. It issues root tokens (signed by the server), verifies tokens (checks all signatures, all expiries, all revocations), and handles submitted delegation tokens from clients.

**3. Policy Engine** — runs Google CEL expressions against every token operation. Example: `"db:write" in capabilities` blocks anyone trying to issue a token with write access. Policies run at both issuance and verification.

**4. Store** — saves agent data. Two backends: in-memory (for dev/tests) and PostgreSQL (for production). Same interface, same code paths.

**5. Revocation Registry** — a list of killed tokens and agents. Before any token passes verification, its ID is checked here. Two backends: in-memory and Redis.

### What Happens on Every Request

**Issuing a token** (POST /api/v1/tokens/issue):
```
1. Check admin API key
2. Check per-agent rate limit (20/sec)
3. Look up agent — is it active?
4. Run CEL policies — does any deny rule fire?
5. Sign a new ACT block with the server's private key
6. Write to audit log
7. Return the token
```

**Verifying a token** (POST /api/v1/tokens/verify):
```
1. Decode the base64 token
2. Check if token ID is in the revocation list
3. For each block in the chain:
   a. Check the block hasn't expired
   b. Check the agent isn't revoked
   c. Check the chain is linked (block[i].issuer == block[i-1].subject)
   d. Check capabilities are a subset of the parent's
   e. Resolve the public key (from LRU cache or store)
   f. Verify the Ed25519 signature
4. Compute effective capabilities (intersection of ALL blocks)
5. Run CEL policies
6. Return: agent ID, capabilities, chain depth
```

### Why Client-Side Delegation Signing

When an orchestrator wants to give a child agent a narrowed token, it signs the new block **on the client** using its own private key. The private key **never goes to the server**. The server only receives the finished, signed token for audit recording.

This means: even if the Agentity server is completely compromised, the attacker cannot forge delegation chains. They'd need the private keys, which only live inside each agent process.

---

## Level 3 — File By File

### `pkg/token/act.go` — The Core Primitive

This is where ACTs are created and extended. The two most important functions:

**`IssueRootToken(agentID, capabilities, conditions, rootKey)`**
- Creates Block 0
- Sets issuer to `agentity://server`
- Sorts capabilities alphabetically (canonical order for signing)
- Generates a random 16-byte nonce (prevents replay attacks)
- Signs the block using `signBlock()` with the server's Ed25519 private key
- Returns an ACT with a fresh UUID as the token ID

**`Delegate(parent, childAgentID, capabilities, conditions, parentKey)`**
- Checks every requested capability exists in the parent's effective set — if not, returns an error immediately (this is the attenuation enforcement)
- Checks the new expiry isn't later than the parent's expiry
- Checks `max_delegations` hasn't been exceeded
- Signs a new block with the parent agent's private key
- Returns a new ACT with all parent blocks + the new block appended

**`effectiveCapabilities(blocks)`**
- Takes the intersection of all capability lists across all blocks
- Starts with Block 0's capabilities as the base set
- For each subsequent block, removes any capability that isn't also in that block
- This is the mathematical guarantee — you can't cheat this

**`canonicalBlockBytes(block)`**
- Produces deterministic JSON (sorted keys, no whitespace) of the block excluding the signature field
- This is what gets signed and verified — byte-exact across Go and Python

---

### `pkg/token/verify.go` — The Verification Logic

**`Verify(encoded, keyResolver, revocationCheck)`**

This function is the gatekeeper. It runs every check in sequence:

1. Decodes the base64 token into an ACT struct
2. Checks the token version (must be 1)
3. Checks the token ID against the revocation registry
4. Loops through every block:
   - Validates the block index is sequential
   - Checks expiry (`exp` must be in the future)
   - Checks `not_before` (if set, must be in the past)
   - Checks both the subject agent and issuer agent aren't revoked
   - Validates chain linkage: `block[i].issuer` must equal `block[i-1].subject` — this ensures no one inserted a fake block in the middle
   - Validates capability subset against parent's effective capabilities
   - Validates expiry monotonicity (child can't expire after parent)
   - Resolves the signer's public key via `keyResolver`
   - Verifies the Ed25519 signature against canonical block bytes
5. Computes final effective capabilities (intersection)
6. Returns a `VerifiedACT` with agent ID, capabilities, and chain depth

If any single check fails, the whole verification fails. There is no partial success.

---

### `pkg/token/claims.go` — Token Data Structures

Defines the structs that represent an ACT in memory:

```go
// The full token
type ACT struct {
    Version int     // always 1
    TokenID string  // UUID — used for revocation lookup
    Blocks  []Block
}

// One link in the chain
type Block struct {
    Index        int             // 0, 1, 2...
    Issuer       string          // who signed this block
    Subject      string          // agent this block grants access to
    Capabilities []string        // what this block allows
    Conditions   BlockConditions // expiry, max delegations
    Nonce        string          // random bytes, prevents replay
    IssuedAt     int64           // unix timestamp
    SignerKeyID  string          // SHA-256 of the signer's public key
    Signature    string          // Ed25519 signature
}

// Conditions embedded in each block
type BlockConditions struct {
    ExpiresAt      int64 // unix timestamp
    NotBefore      int64 // unix timestamp (optional)
    MaxDelegations int   // how many more hops are allowed
}

// What you get back after successful verification
type VerifiedACT struct {
    TokenID        string
    AgentID        string
    Capabilities   []string // intersection of all blocks
    ExpiresAt      int64
    ChainDepth     int
    DelegationPath []string // agent IDs in the chain
}
```

---

### `internal/identity/service.go` — Agent Lifecycle

**`RegisterAgent(req)`**
- Validates the name is not empty
- Generates a fresh Ed25519 key pair (via `pkg/crypto`)
- Hashes the system prompt (if provided) and computes a tool fingerprint
- Creates an `AgentIdentity` with UUID prefixed `agent://`
- Saves to the store
- Returns the agent AND the private key (returned only once, never stored)

**`RevokeAgent(id, cascade)`**
- Marks the agent as revoked in the store
- If `cascade=true`, calls `revokeChildren(id)`

**`revokeChildren(parentID)`** — the BFS implementation:
```go
queue := []item{{id: parentID, depth: 0}}
for len(queue) > 0 {
    cur := queue[0]; queue = queue[1:]
    if cur.depth >= 100 { return error }
    children := store.GetChildAgents(cur.id)
    for each child:
        mark child as revoked
        add child to queue with depth+1
}
```
This is iterative — no recursion — so a tree 10,000 levels deep won't crash the server. The old recursive version would stack overflow at ~1,000 levels.

---

### `internal/delegation/engine.go` — Orchestrating Verification

This is the bridge between the HTTP handlers and the token package. It wires together the key resolver, revocation checker, and audit logger.

**`Verify(ctx, encoded)`**
- Creates a fresh revocation checker from the registry
- Calls `token.Verify()` with the checker and key resolver
- If verification fails, writes a denied event to the audit log
- If successful, writes a verified event to the audit log
- Returns the `VerifiedACT`

**`Delegate(ctx, req)`**
- Verifies the parent token first
- Checks the child agent exists and is active
- Calls `token.Delegate()` to append the new block
- Encodes and returns the new token
- Writes a delegation event to the audit log

**`GetChain(ctx, encoded)`**
- Decodes the token without verifying
- Returns a summary of each block (issuer → subject) for debugging

---

### `internal/delegation/verifier.go` — LRU Key Cache

Every call to `Verify` needs to look up a public key for each block in the chain. Without caching, a 3-hop chain hits the database 3 times per request.

**The LRU cache** (max 10,000 entries) is backed by `container/list` from Go's standard library:

```
cache map[string]*list.Element  ← keyID → pointer to list node
lruList *list.List              ← doubly-linked list, front = most recent
```

**`ResolveKey(keyID)`**:
1. If it's the root server key → return immediately, no cache needed
2. Lock the mutex, check the cache map
3. On hit: move the list element to the front (mark as recently used), return
4. On miss: query the store by key ID (O(1) indexed lookup), insert into cache
5. If cache is at 10,000 entries: evict the tail (least recently used) before inserting

**`insertLocked(keyID, pubKey)`**:
- If already in cache: update value, move to front
- If at capacity: `lruList.Back()` gives the oldest, remove it from both the list and the map
- Push new entry to the front

**`InvalidateCache(keyID)`**:
- Called when a key is rotated so the next lookup fetches the fresh public key

---

### `internal/policy/engine.go` — CEL Policy Engine

**`NewEngine()`**
- Creates a Google CEL environment with these variables available in expressions:
  `agent_id`, `agent_model`, `chain_depth`, `capabilities`, `resource`, `action`, `expires_at`

**`AddPolicy(name, expression, action, priority)`**
- Compiles the CEL expression immediately — if it's invalid syntax, the error is returned here, not at evaluation time
- Validates it returns a boolean
- Adds to the sorted policy list (highest priority number = evaluated first)
- Thread-safe with `sync.RWMutex`

**`Evaluate(ctx, input)`** — the evaluation loop:
```
if no policies → return true (default allow)

Step 1: Run all DENY policies in priority order
  → if any match → return false immediately

Step 2: Run all ALLOW policies in priority order
  → if any match → return true

Step 3: if ALLOW policies exist but none matched → return false
        if NO allow policies → return true (default allow)
```

This means: deny always beats allow. If you have a deny-all policy with priority 100 and an allow-read policy with priority 50, the deny fires first.

---

### `internal/api/handlers_token.go` — HTTP Layer for Tokens

This file wires everything together for the three core token operations.

**`IssueToken` handler**:
- Validates the request body (agent_id, capabilities required)
- Calls `agentLimiter.Allow(agentID)` — returns 429 if over limit
- Calls `identityService.GetAgent()` — returns 404 if agent not found
- Checks `agent.Status == active` — returns 403 if suspended/revoked
- Calls `policyEngine.Evaluate()` with `action="issue"` — returns 403 with problem details if denied
- Calls `token.IssueRootToken()` with the server's root private key
- Records metrics (`TokensIssued.Inc()`, `IssuanceDuration.Observe()`)
- Writes to audit log
- Returns the encoded token + token ID

**`VerifyToken` handler**:
- Calls `delegationEngine.Verify()` — full chain verification
- Calls `agentLimiter.Allow(verified.AgentID)` post-verification
- Calls `policyEngine.Evaluate()` with `action="verify"` and `chain_depth` set
- Records metrics
- Returns the full `VerifiedACT` struct (agent ID, capabilities, chain depth, delegation path)

**`SubmitDelegatedToken` handler**:
- Receives a pre-signed token (the client signed it locally)
- Calls `delegationEngine.Verify()` to validate every signature in the chain
- Writes to audit log
- Returns the verified metadata

---

### `internal/api/middleware.go` — Rate Limiters and Auth

**`AdminAuthMiddleware(apiKey)`**
- Checks the `X-Admin-API-Key` header on every `/api/v1/` request
- Returns 403 (not 401) if missing or wrong
- All token operations require this — there's no public token endpoint

**`RateLimiter` (IP-based, 100 req/sec)**
- Token bucket per IP address
- `Allow(ip)` returns false when the bucket is empty
- `cleanupLoop()` goroutine runs every `5 * interval` to evict idle buckets

**`AgentRateLimiter` (per-agent, 20 req/sec)**
- Same token bucket mechanism but keyed by agent ID instead of IP
- Prevents a single rogue agent from flooding the system
- Separate from IP limiting — both apply independently

---

### `internal/api/router.go` — Route Registration

Wires every handler to its URL. Key decisions visible here:

- `/metrics` and `/api/v1/openapi.json` are registered **outside** the admin auth group — no key needed
- `/api/v1/*` is inside `AdminAuthMiddleware` — everything requires auth
- The global middleware stack applies in order: Recoverer → RealIP → RequestID → Logging → CORS → MaxBytes → RateLimiter

---

### `internal/metrics/metrics.go` — Prometheus Counters

Registers all metrics with `promauto` (auto-registers with the default Prometheus registry):

```go
TokensIssued      = promauto.NewCounter(...)  // incremented in IssueToken
TokensVerified    = promauto.NewCounter(...)  // incremented in VerifyToken (success)
TokensRejected    = promauto.NewCounter(...)  // incremented in VerifyToken (failure)
TokensDelegated   = promauto.NewCounter(...)  // incremented in SubmitDelegatedToken
TokensRevoked     = promauto.NewCounter(...)  // incremented in RevokeToken
AgentsRegistered  = promauto.NewCounter(...)  // incremented in RegisterAgent
PolicyDenials     = promauto.NewCounter(...)  // incremented when CEL blocks a request

VerificationDuration = promauto.NewHistogram(...)  // latency histogram
IssuanceDuration     = promauto.NewHistogram(...)  // latency histogram
```

These are exposed at `GET /metrics` via `promhttp.Handler()` in the router.

---

### `internal/api/handlers_openapi.go` — API Spec and Swagger

**`OpenAPISpec`** — serves the full OpenAPI 3.1 spec as JSON at `/api/v1/openapi.json`. The spec is defined inline as a Go map literal. No auth required.

**`SwaggerUI`** — redirects to `https://petstore.swagger.io/?url=<local-spec>`. This lets anyone point Swagger UI at the running server's spec without serving any static files.

---

### `pkg/mcp/mcp.go` — MCP Auth Middleware

Lets any MCP server drop Agentity enforcement in with three lines:

**`ToolCapabilityMap`** — maps tool names to required capabilities:
```go
capMap := mcp.NewToolCapabilityMap().
    Map("read_file", "read_file").    // tool "read_file" requires cap "read_file"
    Map("execute_code", "code_exec")  // tool "execute_code" requires cap "code_exec"
```

**`VerifyToolCall(ctx, engine, token, toolName, capMap)`**
- Calls `delegationEngine.Verify()` to verify the ACT
- Looks up the required capability for the tool name
- Checks the effective capabilities contain the required one
- Returns an `AuthResult` or an error

**`Middleware.Handler(next)`**
- Extracts the token from `Authorization: Bearer <token>` header or JSON `"token"` field
- Extracts the tool name from `X-MCP-Tool` header or JSON `"tool"` field
- Calls `VerifyToolCall`
- Stores the `AuthResult` in the request context
- Returns 401 if unauthorized, 400 if tool name is missing

**`AuthResultFromContext(ctx)`** — downstream handlers retrieve the auth result from context to get agent ID, capabilities, etc.

---

### `sdk/python/agentity/crypto.py` — Python Delegation

The hardest part of the Python SDK was matching Go's signing exactly.

**`delegate_token_locally(encoded_parent_token, child_agent_id, capabilities, expires_at, parent_private_key_b64)`**:
1. Decodes the parent token (base64url → JSON → ACT dict)
2. Validates capabilities are a subset of parent's effective capabilities
3. Validates new expiry doesn't exceed parent expiry
4. Checks `max_delegations` isn't exceeded
5. Builds the new block dict
6. Produces canonical JSON: `json.dumps(block, sort_keys=True, separators=(',', ':'))` — this must match Go's output byte-for-byte
7. Loads the private key: Go stores 64-byte raw Ed25519 (seed + public key concatenated) as base64url. Python's `cryptography` library takes a 32-byte seed. So the code takes the first 32 bytes: `raw[:32]`
8. Signs with `Ed25519PrivateKey.from_private_bytes(seed).sign(canonical_bytes)`
9. Appends the new block and returns the encoded ACT

---

### `internal/store/memory.go` and `postgres.go` — Storage

Both implement the same `Store` interface. The interface has methods for agents (create, get, update, list, get-by-key-id, get-children) and audit entries (append, list).

**Memory store**: goroutine-safe maps with `sync.RWMutex`. Used in all unit tests and E2E tests via `httptest.NewServer`. Zero external dependencies.

**Postgres store**: `pgx/v5` connection pool. Raw SQL queries (no ORM). Uses `JSONB` columns for agent fingerprints and metadata. Connection pool default: 20 connections.

---

### `test/e2e/setup_test.go` — Test Infrastructure

Every E2E test spins up a full server in-process using `httptest.NewServer`. No Docker, no ports, no external dependencies. The setup:

```go
func newTestServer(t *testing.T) *testServer {
    // real in-memory store
    store := store.NewMemoryStore()
    // real identity service
    idSvc := identity.NewService(store)
    // real policy engine
    policyEngine, _ := policy.NewEngine()
    // real delegation engine with key resolver
    // ... wire everything together
    // spin up the chi router
    ts := httptest.NewServer(router)
    t.Cleanup(ts.Close)
    return &testServer{URL: ts.URL, ...}
}
```

This means every test exercises the complete real code path — HTTP parsing, middleware, handlers, delegation engine, crypto, policy engine, revocation — with zero mocking.

---

## Summary Map

| What you want to understand | File to read |
|---|---|
| The token data structure | `pkg/token/claims.go` |
| How a token is created | `pkg/token/act.go` → `IssueRootToken` |
| How delegation/attenuation works | `pkg/token/act.go` → `Delegate` |
| How a token is verified | `pkg/token/verify.go` → `Verify` |
| How the server verifies + audits | `internal/delegation/engine.go` → `Verify` |
| How public keys are cached | `internal/delegation/verifier.go` |
| How agents are registered | `internal/identity/service.go` → `RegisterAgent` |
| How cascade revocation works | `internal/identity/service.go` → `revokeChildren` |
| How CEL policies work | `internal/policy/engine.go` → `Evaluate` |
| How HTTP requests flow | `internal/api/handlers_token.go` |
| How routes are wired | `internal/api/router.go` |
| How rate limiting works | `internal/api/middleware.go` |
| How metrics are tracked | `internal/metrics/metrics.go` |
| How MCP tools are gated | `pkg/mcp/mcp.go` |
| How Python delegation signing works | `sdk/python/agentity/crypto.py` |
| How E2E tests are set up | `test/e2e/setup_test.go` |
