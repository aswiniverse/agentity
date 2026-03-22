package mcp_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/agentity/agentity/internal/audit"
	"github.com/agentity/agentity/internal/delegation"
	"github.com/agentity/agentity/internal/identity"
	"github.com/agentity/agentity/internal/revocation"
	"github.com/agentity/agentity/internal/store"
	agcrypto "github.com/agentity/agentity/pkg/crypto"
	"github.com/agentity/agentity/pkg/mcp"
	"github.com/agentity/agentity/pkg/token"
)

// helpers

func newEngine(t *testing.T) (*delegation.Engine, *agcrypto.RootKeyStore) {
	t.Helper()
	ks, err := agcrypto.NewRootKeyStore()
	if err != nil {
		t.Fatalf("NewRootKeyStore: %v", err)
	}
	agentStore := store.NewMemoryStore()
	revReg := revocation.NewRegistry(nil)
	auditLog := audit.NewLogger(ks.PrivateKey(), nil)
	keyResolver := delegation.NewKeyResolver(ks, agentStore)
	eng := delegation.NewEngine(agentStore, revReg, auditLog, keyResolver)
	return eng, ks
}

func registerAndIssueToken(t *testing.T, ks *agcrypto.RootKeyStore, agentStore identity.Store, caps []string) (string, *identity.AgentIdentity) {
	t.Helper()
	kp, err := agcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	agent := &identity.AgentIdentity{
		ID:        "agent://mcp-test",
		Name:      "mcp-test",
		PublicKey: agcrypto.EncodePublicKeyBase64(kp.PublicKey),
		KeyID:     kp.KeyID,
		Status:    identity.AgentStatusActive,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := agentStore.CreateAgent(agent); err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	act, err := token.IssueRootToken(agent.ID, caps, token.BlockConditions{
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}, ks.PrivateKey())
	if err != nil {
		t.Fatalf("IssueRootToken: %v", err)
	}
	encoded, err := token.Encode(act)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return encoded, agent
}

// ToolCapabilityMap tests

func TestToolCapabilityMap_DefaultMapping(t *testing.T) {
	m := mcp.NewToolCapabilityMap()
	// Without explicit mapping, tool name == capability.
	if got := m.Required("read_file"); got != "read_file" {
		t.Fatalf("expected 'read_file', got %s", got)
	}
	if got := m.Required("web_search"); got != "web_search" {
		t.Fatalf("expected 'web_search', got %s", got)
	}
}

func TestToolCapabilityMap_ExplicitMapping(t *testing.T) {
	m := mcp.NewToolCapabilityMap().
		Map("fs.read", "read_file").
		Map("fs.write", "write_file")

	if got := m.Required("fs.read"); got != "read_file" {
		t.Fatalf("expected 'read_file', got %s", got)
	}
	if got := m.Required("fs.write"); got != "write_file" {
		t.Fatalf("expected 'write_file', got %s", got)
	}
	// Unmapped tool still falls back to identity.
	if got := m.Required("code_exec"); got != "code_exec" {
		t.Fatalf("expected 'code_exec', got %s", got)
	}
}

func TestToolCapabilityMap_Chaining(t *testing.T) {
	m := mcp.NewToolCapabilityMap().
		Map("a", "cap-a").
		Map("b", "cap-b").
		Map("c", "cap-c")

	for tool, want := range map[string]string{"a": "cap-a", "b": "cap-b", "c": "cap-c"} {
		if got := m.Required(tool); got != want {
			t.Fatalf("tool=%s: expected %s, got %s", tool, want, got)
		}
	}
}

// VerifyToolCall tests

func TestVerifyToolCall_ValidToken(t *testing.T) {
	eng, ks := newEngine(t)
	agentStore := store.NewMemoryStore()

	// Re-create engine with the same store for agent lookup.
	ks2 := ks
	revReg := revocation.NewRegistry(nil)
	auditLog := audit.NewLogger(ks2.PrivateKey(), nil)
	keyResolver := delegation.NewKeyResolver(ks2, agentStore)
	eng = delegation.NewEngine(agentStore, revReg, auditLog, keyResolver)

	encodedToken, _ := registerAndIssueToken(t, ks, agentStore, []string{"read_file", "write_file"})

	capMap := mcp.NewToolCapabilityMap()
	result, err := mcp.VerifyToolCall(context.Background(), eng, encodedToken, "read_file", capMap)
	if err != nil {
		t.Fatalf("VerifyToolCall: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil AuthResult")
	}
	if result.AgentID != "agent://mcp-test" {
		t.Fatalf("expected AgentID=agent://mcp-test, got %s", result.AgentID)
	}
}

func TestVerifyToolCall_EmptyToken(t *testing.T) {
	eng, _ := newEngine(t)
	_, err := mcp.VerifyToolCall(context.Background(), eng, "", "read_file", mcp.NewToolCapabilityMap())
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestVerifyToolCall_MissingCapability(t *testing.T) {
	eng, ks := newEngine(t)
	agentStore := store.NewMemoryStore()
	revReg := revocation.NewRegistry(nil)
	auditLog := audit.NewLogger(ks.PrivateKey(), nil)
	keyResolver := delegation.NewKeyResolver(ks, agentStore)
	eng = delegation.NewEngine(agentStore, revReg, auditLog, keyResolver)

	// Token only has "read_file".
	encodedToken, _ := registerAndIssueToken(t, ks, agentStore, []string{"read_file"})

	capMap := mcp.NewToolCapabilityMap()
	_, err := mcp.VerifyToolCall(context.Background(), eng, encodedToken, "write_file", capMap)
	if err == nil {
		t.Fatal("expected error: token lacks required capability")
	}
}

func TestVerifyToolCall_InvalidToken(t *testing.T) {
	eng, _ := newEngine(t)
	_, err := mcp.VerifyToolCall(context.Background(), eng, "not-a-valid-token", "read_file", mcp.NewToolCapabilityMap())
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestVerifyToolCall_ExplicitCapabilityMapping(t *testing.T) {
	eng, ks := newEngine(t)
	agentStore := store.NewMemoryStore()
	revReg := revocation.NewRegistry(nil)
	auditLog := audit.NewLogger(ks.PrivateKey(), nil)
	keyResolver := delegation.NewKeyResolver(ks, agentStore)
	eng = delegation.NewEngine(agentStore, revReg, auditLog, keyResolver)

	// Token has "read_file" capability.
	encodedToken, _ := registerAndIssueToken(t, ks, agentStore, []string{"read_file"})

	// Map "fs.read" → "read_file".
	capMap := mcp.NewToolCapabilityMap().Map("fs.read", "read_file")
	result, err := mcp.VerifyToolCall(context.Background(), eng, encodedToken, "fs.read", capMap)
	if err != nil {
		t.Fatalf("VerifyToolCall with mapped capability: %v", err)
	}
	if result.AgentID == "" {
		t.Fatal("expected non-empty AgentID")
	}
}

// HTTP Middleware tests

func newMiddlewareEngine(t *testing.T) (*delegation.Engine, *agcrypto.RootKeyStore, identity.Store) {
	t.Helper()
	ks, err := agcrypto.NewRootKeyStore()
	if err != nil {
		t.Fatalf("NewRootKeyStore: %v", err)
	}
	agentStore := store.NewMemoryStore()
	revReg := revocation.NewRegistry(nil)
	auditLog := audit.NewLogger(ks.PrivateKey(), nil)
	keyResolver := delegation.NewKeyResolver(ks, agentStore)
	eng := delegation.NewEngine(agentStore, revReg, auditLog, keyResolver)
	return eng, ks, agentStore
}

func TestMCPMiddleware_MissingTokenReturns401(t *testing.T) {
	eng, _, _ := newMiddlewareEngine(t)
	m := mcp.NewMiddleware(eng, mcp.NewToolCapabilityMap())

	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body, _ := json.Marshal(map[string]string{"tool": "read_file"})
	req := httptest.NewRequest(http.MethodPost, "/mcp/call", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestMCPMiddleware_MissingToolReturns400(t *testing.T) {
	eng, _, _ := newMiddlewareEngine(t)
	m := mcp.NewMiddleware(eng, mcp.NewToolCapabilityMap())

	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body, _ := json.Marshal(map[string]string{"token": "some-token"})
	req := httptest.NewRequest(http.MethodPost, "/mcp/call", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestMCPMiddleware_ValidTokenPassesThrough(t *testing.T) {
	eng, ks, agentStore := newMiddlewareEngine(t)

	encodedToken, agent := registerAndIssueToken(t, ks, agentStore, []string{"read_file"})

	m := mcp.NewMiddleware(eng, mcp.NewToolCapabilityMap())

	var capturedAgentID string
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := mcp.AuthResultFromContext(r.Context())
		if result != nil {
			capturedAgentID = result.AgentID
		}
		w.WriteHeader(http.StatusOK)
	}))

	body, _ := json.Marshal(map[string]string{"tool": "read_file", "token": encodedToken})
	req := httptest.NewRequest(http.MethodPost, "/mcp/call", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if capturedAgentID != agent.ID {
		t.Fatalf("expected AgentID=%s in context, got %s", agent.ID, capturedAgentID)
	}
}

func TestMCPMiddleware_BearerHeaderToken(t *testing.T) {
	eng, ks, agentStore := newMiddlewareEngine(t)
	encodedToken, _ := registerAndIssueToken(t, ks, agentStore, []string{"read_file"})

	m := mcp.NewMiddleware(eng, mcp.NewToolCapabilityMap())

	called := false
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	body, _ := json.Marshal(map[string]string{"tool": "read_file"})
	req := httptest.NewRequest(http.MethodPost, "/mcp/call", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+encodedToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !called {
		t.Fatal("expected downstream handler to be called")
	}
}

func TestMCPMiddleware_XMCPToolHeader(t *testing.T) {
	eng, ks, agentStore := newMiddlewareEngine(t)
	encodedToken, _ := registerAndIssueToken(t, ks, agentStore, []string{"write_file"})

	m := mcp.NewMiddleware(eng, mcp.NewToolCapabilityMap())

	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// No JSON body — use headers only.
	req := httptest.NewRequest(http.MethodPost, "/mcp/call", nil)
	req.Header.Set("Authorization", "Bearer "+encodedToken)
	req.Header.Set("X-MCP-Tool", "write_file")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with X-MCP-Tool header, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMCPMiddleware_MissingCapabilityReturns401(t *testing.T) {
	eng, ks, agentStore := newMiddlewareEngine(t)
	// Token only has "read_file".
	encodedToken, _ := registerAndIssueToken(t, ks, agentStore, []string{"read_file"})

	m := mcp.NewMiddleware(eng, mcp.NewToolCapabilityMap())

	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body, _ := json.Marshal(map[string]string{"tool": "write_file", "token": encodedToken})
	req := httptest.NewRequest(http.MethodPost, "/mcp/call", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing capability, got %d", w.Code)
	}
}

func TestMCPMiddleware_NilCapMapUsesDefaultMapping(t *testing.T) {
	eng, ks, agentStore := newMiddlewareEngine(t)
	encodedToken, _ := registerAndIssueToken(t, ks, agentStore, []string{"search"})

	// nil capMap → NewToolCapabilityMap() (identity mapping)
	m := mcp.NewMiddleware(eng, nil)

	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body, _ := json.Marshal(map[string]string{"tool": "search", "token": encodedToken})
	req := httptest.NewRequest(http.MethodPost, "/mcp/call", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TokenToMCPClaims tests

func TestTokenToMCPClaims_ValidToken(t *testing.T) {
	ks, err := agcrypto.NewRootKeyStore()
	if err != nil {
		t.Fatalf("NewRootKeyStore: %v", err)
	}
	act, err := token.IssueRootToken("agent://claims-test", []string{"read_file"}, token.BlockConditions{
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}, ks.PrivateKey())
	if err != nil {
		t.Fatalf("IssueRootToken: %v", err)
	}
	encoded, _ := token.Encode(act)

	claims, err := mcp.TokenToMCPClaims(encoded)
	if err != nil {
		t.Fatalf("TokenToMCPClaims: %v", err)
	}
	if claims.AgentID != "agent://claims-test" {
		t.Fatalf("expected AgentID=agent://claims-test, got %s", claims.AgentID)
	}
	if len(claims.Capabilities) != 1 || claims.Capabilities[0] != "read_file" {
		t.Fatalf("expected capabilities=[read_file], got %v", claims.Capabilities)
	}
	if claims.ChainDepth != 1 {
		t.Fatalf("expected chain_depth=1, got %d", claims.ChainDepth)
	}
}

func TestTokenToMCPClaims_InvalidToken(t *testing.T) {
	_, err := mcp.TokenToMCPClaims("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

// OAuth 2.1 / PKCE tests

func TestGenerateAuthorizationURL_ContainsResourceParam(t *testing.T) {
	config := mcp.OAuthConfig{
		ClientID:          "test-client",
		AuthorizationURL:  "https://auth.example.com/authorize",
		ResourceIndicator: "https://mcp.example.com",
		Scopes:            []string{"mcp:tools"},
	}
	verifier, err := mcp.GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier: %v", err)
	}
	u, err := mcp.GenerateAuthorizationURL(config, "state123", verifier)
	if err != nil {
		t.Fatalf("GenerateAuthorizationURL: %v", err)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	q := parsed.Query()
	if got := q.Get("resource"); got != "https://mcp.example.com" {
		t.Fatalf("expected resource=https://mcp.example.com, got %q", got)
	}
	if got := q.Get("client_id"); got != "test-client" {
		t.Fatalf("expected client_id=test-client, got %q", got)
	}
	if got := q.Get("response_type"); got != "code" {
		t.Fatalf("expected response_type=code, got %q", got)
	}
	if got := q.Get("state"); got != "state123" {
		t.Fatalf("expected state=state123, got %q", got)
	}
}

func TestGenerateAuthorizationURL_ContainsPKCE(t *testing.T) {
	config := mcp.OAuthConfig{
		ClientID:         "test-client",
		AuthorizationURL: "https://auth.example.com/authorize",
	}
	verifier, err := mcp.GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier: %v", err)
	}
	u, err := mcp.GenerateAuthorizationURL(config, "state456", verifier)
	if err != nil {
		t.Fatalf("GenerateAuthorizationURL: %v", err)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	q := parsed.Query()
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Fatalf("expected code_challenge_method=S256, got %q", got)
	}
	challenge := q.Get("code_challenge")
	if challenge == "" {
		t.Fatal("expected non-empty code_challenge")
	}
	// Verify the challenge matches what ComputeCodeChallenge produces.
	expected := mcp.ComputeCodeChallenge(verifier)
	if challenge != expected {
		t.Fatalf("code_challenge mismatch: got %q, want %q", challenge, expected)
	}
}

func TestComputeCodeChallenge(t *testing.T) {
	// Known test vector: SHA256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") from RFC 7636 example.
	// We use our own deterministic input to verify the encoding.
	verifier := "abc123"
	// SHA256("abc123") = 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
	// base64url (no padding): bKE9UsqwyIjg8Au1AeQlie..."
	got := mcp.ComputeCodeChallenge(verifier)
	if got == "" {
		t.Fatal("expected non-empty challenge")
	}
	// Verify it is valid base64url (no padding characters).
	for _, c := range got {
		if c == '+' || c == '/' || c == '=' {
			t.Fatalf("challenge %q contains non-base64url character %c", got, c)
		}
	}
	// Verify deterministic: same verifier always gives same challenge.
	got2 := mcp.ComputeCodeChallenge(verifier)
	if got != got2 {
		t.Fatal("ComputeCodeChallenge is not deterministic")
	}
}

func TestValidateResourceIndicator_Match(t *testing.T) {
	// Build a minimal JWT with aud = "https://mcp.example.com"
	// Header: {"alg":"none"} -> eyJhbGciOiJub25lIn0
	// Payload: {"aud":"https://mcp.example.com","sub":"test"}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"https://mcp.example.com","sub":"test"}`))
	token := header + "." + payload + ".sig"

	if err := mcp.ValidateResourceIndicator(token, "https://mcp.example.com"); err != nil {
		t.Fatalf("expected nil error for matching aud, got: %v", err)
	}
}

func TestValidateResourceIndicator_MatchSlice(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"aud":["https://other.example.com","https://mcp.example.com"],"sub":"test"}`))
	token := header + "." + payload + ".sig"

	if err := mcp.ValidateResourceIndicator(token, "https://mcp.example.com"); err != nil {
		t.Fatalf("expected nil error for aud slice containing resource, got: %v", err)
	}
}

func TestValidateResourceIndicator_Mismatch(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"https://other.example.com","sub":"test"}`))
	token := header + "." + payload + ".sig"

	if err := mcp.ValidateResourceIndicator(token, "https://mcp.example.com"); err == nil {
		t.Fatal("expected error for mismatched aud, got nil")
	}
}

func TestMiddleware_WWWAuthenticate_WithOAuth(t *testing.T) {
	eng, _, _ := newMiddlewareEngine(t)
	oauthCfg := &mcp.OAuthConfig{
		ResourceIndicator: "https://mcp.example.com",
	}
	m := mcp.NewMiddlewareWithOAuth(eng, mcp.NewToolCapabilityMap(), oauthCfg)

	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// No token → 401 with WWW-Authenticate.
	body, _ := json.Marshal(map[string]string{"tool": "read_file"})
	req := httptest.NewRequest(http.MethodPost, "/mcp/call", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	wwwAuth := w.Header().Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Fatal("expected WWW-Authenticate header to be set")
	}
	if !strings.Contains(wwwAuth, `resource="https://mcp.example.com"`) {
		t.Fatalf("WWW-Authenticate header %q does not contain expected resource", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `Bearer`) {
		t.Fatalf("WWW-Authenticate header %q does not start with Bearer", wwwAuth)
	}
}
