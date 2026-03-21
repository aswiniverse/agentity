// Package e2e contains end-to-end tests for the Agentity server.
// Tests spin up a real in-memory server via httptest.NewServer and exercise
// the full HTTP stack without mocking any internals.
package e2e_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agentity/agentity/internal/api"
	"github.com/agentity/agentity/internal/audit"
	"github.com/agentity/agentity/internal/delegation"
	"github.com/agentity/agentity/internal/identity"
	"github.com/agentity/agentity/internal/policy"
	"github.com/agentity/agentity/internal/revocation"
	"github.com/agentity/agentity/internal/store"
	agcrypto "github.com/agentity/agentity/pkg/crypto"
	"github.com/agentity/agentity/pkg/token"
	"github.com/rs/zerolog"
)

const devAdminKey = "dev-admin-key"

// testServer wraps an httptest.Server and the in-process service graph so
// individual tests can reach into internal state when needed (e.g. to sign
// delegation blocks client-side).
type testServer struct {
	URL          string
	AdminKey     string
	RootKeyStore *agcrypto.RootKeyStore
	AgentStore   identity.Store
	RevReg       *revocation.Registry
	srv          *httptest.Server
}

// newTestServer boots a real Agentity server backed by an in-memory store.
// The server is automatically shut down at the end of the test.
func newTestServer(t *testing.T) *testServer {
	t.Helper()

	rootKeyStore, err := agcrypto.NewRootKeyStore()
	if err != nil {
		t.Fatalf("create root key store: %v", err)
	}

	agentStore := store.NewMemoryStore()
	revReg := revocation.NewRegistry(nil) // nil = in-memory only
	auditLog := audit.NewLogger(rootKeyStore.PrivateKey())
	idService := identity.NewService(agentStore)
	keyResolver := delegation.NewKeyResolver(rootKeyStore, agentStore)
	delegEngine := delegation.NewEngine(agentStore, revReg, auditLog, keyResolver)

	policyEngine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("create policy engine: %v", err)
	}

	router := api.NewRouter(api.RouterConfig{
		Logger:           zerolog.Nop(),
		RootKeyStore:     rootKeyStore,
		IdentityService:  idService,
		DelegationEngine: delegEngine,
		RevocationReg:    revReg,
		PolicyEngine:     policyEngine,
		AuditLogger:      auditLog,
		AdminAPIKey:      devAdminKey,
		AllowedOrigins:   []string{"*"},
	})

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	return &testServer{
		URL:          srv.URL,
		AdminKey:     devAdminKey,
		RootKeyStore: rootKeyStore,
		AgentStore:   agentStore,
		RevReg:       revReg,
		srv:          srv,
	}
}

// do sends an authenticated admin request and returns the raw response.
func (ts *testServer) do(t *testing.T, method, path string, body interface{}) *http.Response {
	t.Helper()
	return ts.doWithKey(t, method, path, body, ts.AdminKey)
}

// doNoAuth sends a request with no Authorization header.
func (ts *testServer) doNoAuth(t *testing.T, method, path string, body interface{}) *http.Response {
	t.Helper()
	return ts.doWithKey(t, method, path, body, "")
}

func (ts *testServer) doWithKey(t *testing.T, method, path string, body interface{}, key string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		bodyReader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, ts.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// doForm sends a form-encoded POST (for OAuth endpoints).
func (ts *testServer) doForm(t *testing.T, path string, values map[string]string) *http.Response {
	t.Helper()
	var parts []string
	for k, v := range values {
		parts = append(parts, k+"="+v)
	}
	body := strings.Join(parts, "&")
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// mustStatus asserts the response has the expected HTTP status code.
func mustStatus(t *testing.T, resp *http.Response, expected int) {
	t.Helper()
	if resp.StatusCode != expected {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected status %d, got %d: %s", expected, resp.StatusCode, string(body))
	}
}

// decodeJSON decodes the response body into target and closes the body.
func decodeJSON(t *testing.T, resp *http.Response, target interface{}) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

// agentUUID extracts the UUID portion from a full agent ID like "agent://uuid".
func agentUUID(agentID string) string {
	return strings.TrimPrefix(agentID, "agent://")
}

// futureExpiry returns a Unix timestamp that is n seconds in the future.
func futureExpiry(secs int64) int64 {
	return time.Now().Add(time.Duration(secs) * time.Second).Unix()
}

// registerAgent is a convenience helper: registers an agent and returns the
// decoded agent map and the base64url-encoded private key.
func registerAgent(t *testing.T, ts *testServer, name string) (map[string]interface{}, string) {
	t.Helper()
	resp := ts.do(t, http.MethodPost, "/api/v1/agents", map[string]interface{}{
		"name":  name,
		"model": "claude-3",
		"tools": []string{"read_file", "write_file"},
	})
	mustStatus(t, resp, http.StatusCreated)
	var result map[string]interface{}
	decodeJSON(t, resp, &result)
	agent := result["agent"].(map[string]interface{})
	privateKey := result["private_key"].(string)
	return agent, privateKey
}

// issueToken issues a root ACT token for agentID with the given capabilities
// and a TTL of ttlSecs seconds.
func issueToken(t *testing.T, ts *testServer, agentID string, caps []string, ttlSecs int64) string {
	t.Helper()
	resp := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
		"agent_id":     agentID,
		"capabilities": caps,
		"conditions": token.BlockConditions{
			ExpiresAt: futureExpiry(ttlSecs),
		},
	})
	mustStatus(t, resp, http.StatusCreated)
	var result map[string]interface{}
	decodeJSON(t, resp, &result)
	return result["token"].(string)
}
