package delegation_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/agentity/agentity/internal/delegation"
	"github.com/agentity/agentity/internal/identity"
	"github.com/agentity/agentity/internal/revocation"
	"github.com/agentity/agentity/internal/store"
	agcrypto "github.com/agentity/agentity/pkg/crypto"
	"github.com/agentity/agentity/pkg/token"
)

// engineFixture holds everything needed to run Engine.Verify tests.
type engineFixture struct {
	engine  *delegation.Engine
	ks      *agcrypto.RootKeyStore
	memStore *store.MemoryStore
}

func newEngineFixture(t *testing.T) *engineFixture {
	t.Helper()
	ks, err := agcrypto.NewRootKeyStore()
	if err != nil {
		t.Fatalf("NewRootKeyStore: %v", err)
	}
	s := store.NewMemoryStore()
	rev := revocation.NewRegistry(nil)
	resolver := delegation.NewKeyResolver(ks, s)
	engine := delegation.NewEngine(s, rev, nil, resolver)
	return &engineFixture{engine: engine, ks: ks, memStore: s}
}

func (f *engineFixture) registerAgent(t *testing.T, id, sph, tfp string) *identity.AgentIdentity {
	t.Helper()
	agent := &identity.AgentIdentity{
		ID:     id,
		Name:   "test-agent",
		Status: identity.AgentStatusActive,
		Fingerprint: identity.AgentFingerprint{
			SystemPromptHash: sph,
			ToolFingerprint:  tfp,
		},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := f.memStore.CreateAgent(agent); err != nil {
		t.Fatalf("CreateAgent(%s): %v", id, err)
	}
	return agent
}

func (f *engineFixture) issueToken(t *testing.T, agentID string, opts token.RootTokenOptions) string {
	t.Helper()
	cond := token.BlockConditions{ExpiresAt: time.Now().Add(time.Hour).Unix()}
	act, err := token.IssueRootTokenWithOptions(agentID, []string{"read"}, cond, f.ks.PrivateKey(), opts)
	if err != nil {
		t.Fatalf("IssueRootTokenWithOptions: %v", err)
	}
	encoded, err := token.Encode(act)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return encoded
}

// TestVerify_FingerprintMatch — token with sph/tfp matching agent → success.
func TestVerify_FingerprintMatch(t *testing.T) {
	f := newEngineFixture(t)
	agentID := "agent://fp-match"
	sph := "sha256:aaaa"
	tfp := "sha256:bbbb"
	f.registerAgent(t, agentID, sph, tfp)

	encoded := f.issueToken(t, agentID, token.RootTokenOptions{
		SystemPromptHash: sph,
		ToolFingerprint:  tfp,
	})

	verified, err := f.engine.Verify(context.Background(), encoded)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if verified.AgentID != agentID {
		t.Fatalf("expected AgentID=%s, got %s", agentID, verified.AgentID)
	}
}

// TestVerify_FingerprintMismatch_SystemPrompt — sph in token != agent's → error "system prompt changed".
func TestVerify_FingerprintMismatch_SystemPrompt(t *testing.T) {
	f := newEngineFixture(t)
	agentID := "agent://fp-sph-mismatch"
	f.registerAgent(t, agentID, "sha256:current", "sha256:tools")

	// Token was issued with an old system prompt hash.
	encoded := f.issueToken(t, agentID, token.RootTokenOptions{
		SystemPromptHash: "sha256:old",
		ToolFingerprint:  "sha256:tools",
	})

	_, err := f.engine.Verify(context.Background(), encoded)
	if err == nil {
		t.Fatal("expected fingerprint mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "system prompt changed") {
		t.Fatalf("expected 'system prompt changed' in error, got: %v", err)
	}
}

// TestVerify_FingerprintMismatch_Tools — tfp in token != agent's → error "tools changed".
func TestVerify_FingerprintMismatch_Tools(t *testing.T) {
	f := newEngineFixture(t)
	agentID := "agent://fp-tfp-mismatch"
	f.registerAgent(t, agentID, "sha256:prompt", "sha256:current-tools")

	// Token was issued with old tool fingerprint.
	encoded := f.issueToken(t, agentID, token.RootTokenOptions{
		SystemPromptHash: "sha256:prompt",
		ToolFingerprint:  "sha256:old-tools",
	})

	_, err := f.engine.Verify(context.Background(), encoded)
	if err == nil {
		t.Fatal("expected fingerprint mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "tools changed") {
		t.Fatalf("expected 'tools changed' in error, got: %v", err)
	}
}

// TestVerify_NoFingerprint_BackwardCompat — token with empty sph/tfp → success regardless of agent fingerprint.
func TestVerify_NoFingerprint_BackwardCompat(t *testing.T) {
	f := newEngineFixture(t)
	agentID := "agent://fp-compat"
	// Agent has fingerprint fields set, but the token was issued without them.
	f.registerAgent(t, agentID, "sha256:some-prompt", "sha256:some-tools")

	// Issue token with no fingerprint options (empty sph/tfp).
	encoded := f.issueToken(t, agentID, token.RootTokenOptions{})

	verified, err := f.engine.Verify(context.Background(), encoded)
	if err != nil {
		t.Fatalf("expected backward-compat success, got error: %v", err)
	}
	if verified.AgentID != agentID {
		t.Fatalf("expected AgentID=%s, got %s", agentID, verified.AgentID)
	}
}

// TestEngine_Delegate_Success — parent token + active child agent → delegation succeeds with non-empty encoded token.
func TestEngine_Delegate_Success(t *testing.T) {
	f := newEngineFixture(t)
	parentID := "agent://parent"
	childID := "agent://child"

	f.registerAgent(t, parentID, "", "")
	f.registerAgent(t, childID, "", "")

	// Issue root token for parent, signed by root key store.
	parentEncoded := f.issueToken(t, parentID, token.RootTokenOptions{})

	// Generate a key pair for the parent agent (used to sign the delegation block).
	parentAgentKey, err := agcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	req := delegation.DelegationRequest{
		ParentTokenEncoded: parentEncoded,
		ChildAgentID:       childID,
		Capabilities:       []string{"read"},
		Conditions:         token.BlockConditions{ExpiresAt: time.Now().Add(time.Hour).Unix()},
		ParentAgentKey:     parentAgentKey.PrivateKey,
	}

	encoded, err := f.engine.Delegate(context.Background(), req)
	if err != nil {
		t.Fatalf("Delegate: unexpected error: %v", err)
	}
	if encoded == "" {
		t.Fatal("expected non-empty encoded token")
	}
}

// TestEngine_Delegate_InvalidParentToken — garbage parent token → error.
func TestEngine_Delegate_InvalidParentToken(t *testing.T) {
	f := newEngineFixture(t)
	parentAgentKey, err := agcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	req := delegation.DelegationRequest{
		ParentTokenEncoded: "not-a-token",
		ChildAgentID:       "agent://child",
		Capabilities:       []string{"read"},
		Conditions:         token.BlockConditions{ExpiresAt: time.Now().Add(time.Hour).Unix()},
		ParentAgentKey:     parentAgentKey.PrivateKey,
	}

	_, err = f.engine.Delegate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for invalid parent token, got nil")
	}
}

// TestEngine_Delegate_ChildNotFound — nonexistent child agent ID → error containing "child agent".
func TestEngine_Delegate_ChildNotFound(t *testing.T) {
	f := newEngineFixture(t)
	parentID := "agent://parent-for-notfound"
	f.registerAgent(t, parentID, "", "")

	parentEncoded := f.issueToken(t, parentID, token.RootTokenOptions{})
	parentAgentKey, err := agcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	req := delegation.DelegationRequest{
		ParentTokenEncoded: parentEncoded,
		ChildAgentID:       "agent://does-not-exist",
		Capabilities:       []string{"read"},
		Conditions:         token.BlockConditions{ExpiresAt: time.Now().Add(time.Hour).Unix()},
		ParentAgentKey:     parentAgentKey.PrivateKey,
	}

	_, err = f.engine.Delegate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for nonexistent child agent, got nil")
	}
	if !strings.Contains(err.Error(), "child agent") {
		t.Fatalf("expected 'child agent' in error, got: %v", err)
	}
}

// TestEngine_Delegate_ChildNotActive — suspended child agent → error "not active".
func TestEngine_Delegate_ChildNotActive(t *testing.T) {
	f := newEngineFixture(t)
	parentID := "agent://parent-for-suspended"
	childID := "agent://suspended-child"

	f.registerAgent(t, parentID, "", "")

	// Register child with suspended status.
	child := &identity.AgentIdentity{
		ID:        childID,
		Name:      "suspended-agent",
		Status:    identity.AgentStatusSuspended,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := f.memStore.CreateAgent(child); err != nil {
		t.Fatalf("CreateAgent suspended: %v", err)
	}

	parentEncoded := f.issueToken(t, parentID, token.RootTokenOptions{})
	parentAgentKey, err := agcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	req := delegation.DelegationRequest{
		ParentTokenEncoded: parentEncoded,
		ChildAgentID:       childID,
		Capabilities:       []string{"read"},
		Conditions:         token.BlockConditions{ExpiresAt: time.Now().Add(time.Hour).Unix()},
		ParentAgentKey:     parentAgentKey.PrivateKey,
	}

	_, err = f.engine.Delegate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for non-active child agent, got nil")
	}
	if !strings.Contains(err.Error(), "not active") {
		t.Fatalf("expected 'not active' in error, got: %v", err)
	}
}

// TestEngine_GetChain_SingleBlock — root token → chain with Depth=1 and 1 block entry.
func TestEngine_GetChain_SingleBlock(t *testing.T) {
	f := newEngineFixture(t)
	agentID := "agent://chain-single"
	f.registerAgent(t, agentID, "", "")

	encoded := f.issueToken(t, agentID, token.RootTokenOptions{})

	chain, err := f.engine.GetChain(context.Background(), encoded)
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if chain.Depth != 1 {
		t.Fatalf("expected Depth=1, got %d", chain.Depth)
	}
	if len(chain.Blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(chain.Blocks))
	}
}

// TestEngine_GetChain_InvalidToken — garbage encoded string → error.
func TestEngine_GetChain_InvalidToken(t *testing.T) {
	f := newEngineFixture(t)

	_, err := f.engine.GetChain(context.Background(), "not-valid")
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
}

// TestEngine_Verify_InvalidToken — garbage encoded string → error.
func TestEngine_Verify_InvalidToken(t *testing.T) {
	f := newEngineFixture(t)

	_, err := f.engine.Verify(context.Background(), "not-valid-token")
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
}
