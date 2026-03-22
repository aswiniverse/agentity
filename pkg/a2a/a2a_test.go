package a2a_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentity/agentity/pkg/a2a"
	"github.com/agentity/agentity/pkg/token"
)

// mockEngine implements DelegationEngine for testing.
type mockEngine struct {
	act *token.VerifiedACT
	err error
}

func (m *mockEngine) VerifyACT(_ context.Context, _ string) (*token.VerifiedACT, error) {
	return m.act, m.err
}

func validACT(caps []string) *token.VerifiedACT {
	return &token.VerifiedACT{
		TokenID:      "tok-001",
		AgentID:      "agent://test-agent",
		Capabilities: caps,
		ChainDepth:   1,
	}
}

func makeBody(skillID, taskID string) *bytes.Reader {
	b, _ := json.Marshal(map[string]string{
		"skill_id": skillID,
		"task_id":  taskID,
	})
	return bytes.NewReader(b)
}

// TestMiddleware_ValidACT_CorrectCapability: valid token with matching capability → 200, context set.
func TestMiddleware_ValidACT_CorrectCapability(t *testing.T) {
	engine := &mockEngine{act: validACT([]string{"web_search"})}
	capMap := a2a.NewCapabilityMap().Map("web_search", "web_search")
	mw := a2a.NewMiddleware(engine, capMap)

	called := false
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/a2a", makeBody("web_search", "task-abc"))
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !called {
		t.Fatal("expected downstream handler to be called")
	}
}

// TestMiddleware_MissingToken: no Authorization header → 401.
func TestMiddleware_MissingToken(t *testing.T) {
	engine := &mockEngine{act: validACT([]string{"web_search"})}
	mw := a2a.NewMiddleware(engine, a2a.NewCapabilityMap())

	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/a2a", makeBody("web_search", "task-abc"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "missing token" {
		t.Fatalf("expected error='missing token', got %q", resp["error"])
	}
}

// TestMiddleware_InvalidToken: VerifyACT returns error → 401.
func TestMiddleware_InvalidToken(t *testing.T) {
	engine := &mockEngine{err: errors.New("bad signature")}
	mw := a2a.NewMiddleware(engine, a2a.NewCapabilityMap())

	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/a2a", makeBody("web_search", "task-abc"))
	req.Header.Set("Authorization", "Bearer bad-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "invalid token" {
		t.Fatalf("expected error='invalid token', got %q", resp["error"])
	}
}

// TestMiddleware_MissingCapability: valid token but capability not in set → 403.
func TestMiddleware_MissingCapability(t *testing.T) {
	// Token only has "read_file", but skill requires "web_search".
	engine := &mockEngine{act: validACT([]string{"read_file"})}
	mw := a2a.NewMiddleware(engine, a2a.NewCapabilityMap())

	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/a2a", makeBody("web_search", "task-abc"))
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "insufficient capabilities" {
		t.Fatalf("expected error='insufficient capabilities', got %q", resp["error"])
	}
	if resp["required"] != "web_search" {
		t.Fatalf("expected required='web_search', got %q", resp["required"])
	}
}

// TestMiddleware_ContextValues: verify A2AContext is set correctly in context.
func TestMiddleware_ContextValues(t *testing.T) {
	engine := &mockEngine{act: validACT([]string{"web_search", "code_exec"})}
	capMap := a2a.NewCapabilityMap().Map("code_execution", "code_exec")
	mw := a2a.NewMiddleware(engine, capMap)

	var captured *a2a.A2AContext
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = a2a.FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/a2a", makeBody("code_execution", "task-xyz"))
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if captured == nil {
		t.Fatal("expected A2AContext in context, got nil")
	}
	if captured.AgentID != "agent://test-agent" {
		t.Fatalf("expected AgentID='agent://test-agent', got %q", captured.AgentID)
	}
	if captured.TaskID != "task-xyz" {
		t.Fatalf("expected TaskID='task-xyz', got %q", captured.TaskID)
	}
	if captured.SkillID != "code_execution" {
		t.Fatalf("expected SkillID='code_execution', got %q", captured.SkillID)
	}
	if len(captured.Capabilities) != 2 {
		t.Fatalf("expected 2 capabilities, got %d: %v", len(captured.Capabilities), captured.Capabilities)
	}
}

// TestFromContext_Nil: FromContext returns nil when not set.
func TestFromContext_Nil(t *testing.T) {
	ctx := context.Background()
	if got := a2a.FromContext(ctx); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}
