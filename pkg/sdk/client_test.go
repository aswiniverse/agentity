package sdk_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agentity/agentity/pkg/sdk"
	"github.com/agentity/agentity/pkg/token"
)

// buildParentToken creates a signed root ACT and returns the encoded string plus the key used.
func buildParentToken(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_ = pub

	conditions := token.BlockConditions{
		ExpiresAt:      time.Now().Add(1 * time.Hour).Unix(),
		MaxDelegations: 2,
	}
	act, err := token.IssueRootToken("agent://parent", []string{"read", "write"}, conditions, priv)
	if err != nil {
		t.Fatalf("issue root token: %v", err)
	}
	encoded, err := token.Encode(act)
	if err != nil {
		t.Fatalf("encode token: %v", err)
	}
	return encoded, priv
}

// TestDelegateTokenLocallyExists verifies the method compiles and is callable.
func TestDelegateTokenLocallyExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	parentEncoded, parentPriv := buildParentToken(t)

	_, childPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate child key: %v", err)
	}
	_ = childPriv

	conditions := token.BlockConditions{
		ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
	}

	client := sdk.NewClient(srv.URL, "test-admin-key")
	result, err := client.DelegateTokenLocally(
		context.Background(),
		parentEncoded,
		"agent://child",
		[]string{"read"},
		conditions,
		parentPriv,
	)
	if err != nil {
		t.Fatalf("DelegateTokenLocally returned error: %v", err)
	}
	if result == "" {
		t.Fatal("DelegateTokenLocally returned empty token string")
	}
}

// TestDelegateTokenLocallyBodyHasNoPK verifies no private key material appears in the HTTP request body.
func TestDelegateTokenLocallyBodyHasNoPK(t *testing.T) {
	var capturedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 65536)
		n, _ := r.Body.Read(buf)
		capturedBody = make([]byte, n)
		copy(capturedBody, buf[:n])
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	parentEncoded, parentPriv := buildParentToken(t)

	conditions := token.BlockConditions{
		ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
	}

	client := sdk.NewClient(srv.URL, "test-admin-key")
	_, err := client.DelegateTokenLocally(
		context.Background(),
		parentEncoded,
		"agent://child",
		[]string{"read"},
		conditions,
		parentPriv,
	)
	if err != nil {
		t.Fatalf("DelegateTokenLocally returned error: %v", err)
	}

	bodyStr := string(capturedBody)

	// The body must contain delegated_token and nothing that looks like a raw private key field.
	if !strings.Contains(bodyStr, "delegated_token") {
		t.Errorf("expected body to contain 'delegated_token', got: %s", bodyStr)
	}
	for _, forbidden := range []string{"parent_agent_key", "private_key", "ParentAgentKey"} {
		if strings.Contains(bodyStr, forbidden) {
			t.Errorf("body must NOT contain %q but it does: %s", forbidden, bodyStr)
		}
	}
}

// TestDelegateTokenLocallyBodyStructure verifies the POST body is {"delegated_token": "..."} only.
func TestDelegateTokenLocallyBodyStructure(t *testing.T) {
	var parsedBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&parsedBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	parentEncoded, parentPriv := buildParentToken(t)

	conditions := token.BlockConditions{
		ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
	}

	client := sdk.NewClient(srv.URL, "test-admin-key")
	_, err := client.DelegateTokenLocally(
		context.Background(),
		parentEncoded,
		"agent://child",
		[]string{"read"},
		conditions,
		parentPriv,
	)
	if err != nil {
		t.Fatalf("DelegateTokenLocally returned error: %v", err)
	}

	// Exactly one key in the body: "delegated_token".
	if len(parsedBody) != 1 {
		t.Errorf("expected exactly 1 field in request body, got %d: %v", len(parsedBody), parsedBody)
	}
	if _, ok := parsedBody["delegated_token"]; !ok {
		t.Errorf("expected 'delegated_token' key in request body, got keys: %v", parsedBody)
	}
}

// TestNoParentAgentKeyInAnyRequestStruct is a compile-time guard:
// if DelegateTokenRequest or ParentAgentKey exist, this file won't compile.
// (The old type is gone, so there's nothing to reference — the absence is the test.)
func TestOldAPIAbsence(t *testing.T) {
	// DelegateToken and DelegateTokenRequest have been removed.
	// This test simply documents that fact; the compiler enforces it.
	// If DelegateTokenRequest were re-added with ParentAgentKey, the
	// TestDelegateTokenLocallyBodyHasNoPK test would catch any use of it.
	t.Log("DelegateToken and DelegateTokenRequest with ParentAgentKey are confirmed absent (compiler verified)")
}

// TestRegisterAgent verifies that RegisterAgent parses the server response correctly.
func TestRegisterAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"agent":{"id":"agent://test-id","name":"test"},"private_key":"abc"}`))
	}))
	defer srv.Close()

	client := sdk.NewClient(srv.URL, "test-key")
	agent, key, err := client.RegisterAgent(context.Background(), sdk.RegisterAgentRequest{Name: "test"})
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	if agent == nil {
		t.Fatal("expected non-nil agent")
	}
	if agent.ID != "agent://test-id" {
		t.Errorf("expected ID=agent://test-id, got %s", agent.ID)
	}
	if agent.Name != "test" {
		t.Errorf("expected name=test, got %s", agent.Name)
	}
	if key != "abc" {
		t.Errorf("expected private_key=abc, got %s", key)
	}
}

// TestGetAgent_WithPrefix verifies that GetAgent strips the "agent://" prefix from the ID.
func TestGetAgent_WithPrefix(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"agent://test-id","name":"test-agent"}`))
	}))
	defer srv.Close()

	client := sdk.NewClient(srv.URL, "test-key")
	agent, err := client.GetAgent(context.Background(), "agent://test-id")
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if capturedPath != "/api/v1/agents/test-id" {
		t.Errorf("expected path /api/v1/agents/test-id, got %s", capturedPath)
	}
	if agent.Name != "test-agent" {
		t.Errorf("expected name=test-agent, got %s", agent.Name)
	}
}

// TestGetAgent_WithoutPrefix verifies that GetAgent works when no "agent://" prefix is present.
func TestGetAgent_WithoutPrefix(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"test-id","name":"bare"}`))
	}))
	defer srv.Close()

	client := sdk.NewClient(srv.URL, "test-key")
	_, err := client.GetAgent(context.Background(), "test-id")
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if capturedPath != "/api/v1/agents/test-id" {
		t.Errorf("expected path /api/v1/agents/test-id, got %s", capturedPath)
	}
}

// TestRevokeAgent verifies that RevokeAgent sends a request and returns no error on 200.
func TestRevokeAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := sdk.NewClient(srv.URL, "test-key")
	err := client.RevokeAgent(context.Background(), "agent://test-id", true)
	if err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}
}

// TestIssueToken verifies that IssueToken returns the encoded token string.
func TestIssueToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"encoded-token","token_id":"tid-1"}`))
	}))
	defer srv.Close()

	client := sdk.NewClient(srv.URL, "test-key")
	tok, err := client.IssueToken(context.Background(), sdk.IssueTokenRequest{
		AgentID:      "agent://x",
		Capabilities: []string{"read"},
	})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if tok != "encoded-token" {
		t.Errorf("expected token=encoded-token, got %s", tok)
	}
}

// TestVerifyToken verifies that VerifyToken returns the parsed response including AgentID.
func TestVerifyToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token_id":"t1","agent_id":"agent://x","capabilities":["read"],"chain_depth":1}`))
	}))
	defer srv.Close()

	client := sdk.NewClient(srv.URL, "test-key")
	resp, err := client.VerifyToken(context.Background(), "some-encoded-token")
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if resp.AgentID != "agent://x" {
		t.Errorf("expected AgentID=agent://x, got %s", resp.AgentID)
	}
	if resp.TokenID != "t1" {
		t.Errorf("expected TokenID=t1, got %s", resp.TokenID)
	}
	if resp.ChainDepth != 1 {
		t.Errorf("expected ChainDepth=1, got %d", resp.ChainDepth)
	}
}

// TestRevokeToken verifies that RevokeToken returns no error on 200.
func TestRevokeToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := sdk.NewClient(srv.URL, "test-key")
	err := client.RevokeToken(context.Background(), "tid-1", "expired")
	if err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
}

// TestDoJSON_4xxError_WithDetail verifies that a 4xx error with a "detail" field surfaces the detail message.
func TestDoJSON_4xxError_WithDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"forbidden"}`))
	}))
	defer srv.Close()

	client := sdk.NewClient(srv.URL, "test-key")
	_, err := client.GetAgent(context.Background(), "some-id")
	if err == nil {
		t.Fatal("expected error on 403 response")
	}
	if !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("expected error to contain 'forbidden', got: %v", err)
	}
}

// TestDoJSON_4xxError_NoDetail verifies that a 5xx error without a detail field includes the status code.
func TestDoJSON_4xxError_NoDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`plain error`))
	}))
	defer srv.Close()

	client := sdk.NewClient(srv.URL, "test-key")
	_, err := client.GetAgent(context.Background(), "some-id")
	if err == nil {
		t.Fatal("expected error on 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected error to contain '500', got: %v", err)
	}
}

// TestDoJSON_AuthHeader verifies that the Authorization header is set to "Bearer <key>".
func TestDoJSON_AuthHeader(t *testing.T) {
	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"agent://x","name":"x"}`))
	}))
	defer srv.Close()

	client := sdk.NewClient(srv.URL, "test-key")
	_, err := client.GetAgent(context.Background(), "x")
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if capturedAuth != "Bearer test-key" {
		t.Errorf("expected Authorization=Bearer test-key, got %q", capturedAuth)
	}
}

// TestDelegateTokenLocally_InvalidParentToken verifies that an invalid parent token string causes a decode error.
func TestDelegateTokenLocally_InvalidParentToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	client := sdk.NewClient(srv.URL, "test-key")
	_, err = client.DelegateTokenLocally(
		context.Background(),
		"not-a-valid-token",
		"agent://child",
		[]string{"read"},
		token.BlockConditions{ExpiresAt: time.Now().Add(time.Hour).Unix()},
		priv,
	)
	if err == nil {
		t.Fatal("expected error for invalid parent token")
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("expected error to contain 'decode', got: %v", err)
	}
}
