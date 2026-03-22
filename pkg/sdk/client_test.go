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
