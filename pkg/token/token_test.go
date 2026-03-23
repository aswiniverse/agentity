package token_test

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	agcrypto "github.com/agentity/agentity/pkg/crypto"
	"github.com/agentity/agentity/pkg/token"
)

// helpers

func newKeyPair(t *testing.T) *agcrypto.AgentKeyPair {
	t.Helper()
	kp, err := agcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	return kp
}

func newRootKeyStore(t *testing.T) *agcrypto.RootKeyStore {
	t.Helper()
	ks, err := agcrypto.NewRootKeyStore()
	if err != nil {
		t.Fatalf("new root key store: %v", err)
	}
	return ks
}

func futureExp(secs int64) int64 {
	return time.Now().Add(time.Duration(secs) * time.Second).Unix()
}

// staticKeyResolver resolves keys from a map[keyID]base64pubkey.
type staticKeyResolver struct {
	keys map[string]string
}

func (r *staticKeyResolver) ResolveKey(keyID string) (string, error) {
	if k, ok := r.keys[keyID]; ok {
		return k, nil
	}
	return "", fmt.Errorf("key not found: %s", keyID)
}

// noopRevocationChecker never considers anything revoked.
type noopRevocationChecker struct{}

func (n *noopRevocationChecker) IsTokenRevoked(_ string) (bool, error) { return false, nil }
func (n *noopRevocationChecker) IsAgentRevoked(_ string) (bool, error)  { return false, nil }

// --- IssueRootToken ---

func TestIssueRootToken(t *testing.T) {
	ks := newRootKeyStore(t)
	agentID := "agent://test-agent"
	caps := []string{"read", "write"}
	cond := token.BlockConditions{ExpiresAt: futureExp(3600)}

	act, err := token.IssueRootToken(agentID, caps, cond, ks.PrivateKey())
	if err != nil {
		t.Fatalf("IssueRootToken: %v", err)
	}
	if act.Version != 1 {
		t.Fatalf("expected version=1, got %d", act.Version)
	}
	if act.TokenID == "" {
		t.Fatal("expected non-empty token ID")
	}
	if len(act.Blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(act.Blocks))
	}
	block := act.Blocks[0]
	if block.Issuer != "agentity://server" {
		t.Fatalf("expected issuer=agentity://server, got %s", block.Issuer)
	}
	if block.Subject != agentID {
		t.Fatalf("expected subject=%s, got %s", agentID, block.Subject)
	}
	if block.Signature == "" {
		t.Fatal("expected non-empty signature")
	}
}

func TestIssueRootToken_EmptyCapabilities(t *testing.T) {
	ks := newRootKeyStore(t)
	_, err := token.IssueRootToken("agent://x", []string{}, token.BlockConditions{ExpiresAt: futureExp(3600)}, ks.PrivateKey())
	if err == nil {
		t.Fatal("expected error for empty capabilities")
	}
}

func TestIssueRootToken_ZeroExpiry(t *testing.T) {
	ks := newRootKeyStore(t)
	_, err := token.IssueRootToken("agent://x", []string{"read"}, token.BlockConditions{}, ks.PrivateKey())
	if err == nil {
		t.Fatal("expected error for zero expiry")
	}
}

func TestIssueRootToken_PastExpiry(t *testing.T) {
	ks := newRootKeyStore(t)
	_, err := token.IssueRootToken("agent://x", []string{"read"}, token.BlockConditions{
		ExpiresAt: time.Now().Add(-time.Hour).Unix(),
	}, ks.PrivateKey())
	if err == nil {
		t.Fatal("expected error for past expiry")
	}
}

// --- Encode / Decode ---

func TestEncodeDecodeRoundtrip(t *testing.T) {
	ks := newRootKeyStore(t)
	act, _ := token.IssueRootToken("agent://x", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())

	encoded, err := token.Encode(act)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if encoded == "" {
		t.Fatal("expected non-empty encoded token")
	}

	decoded, err := token.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.TokenID != act.TokenID {
		t.Fatalf("token ID mismatch: %s vs %s", decoded.TokenID, act.TokenID)
	}
	if len(decoded.Blocks) != len(act.Blocks) {
		t.Fatalf("block count mismatch: %d vs %d", len(decoded.Blocks), len(act.Blocks))
	}
}

func TestDecode_InvalidInput(t *testing.T) {
	_, err := token.Decode("not-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid input")
	}
}

// --- Verify ---

func TestVerify_RootToken(t *testing.T) {
	ks := newRootKeyStore(t)
	agentID := "agent://verify-test"
	act, _ := token.IssueRootToken(agentID, []string{"read", "write"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())
	encoded, _ := token.Encode(act)

	resolver := &staticKeyResolver{
		keys: map[string]string{
			ks.KeyID(): agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
		},
	}

	verified, err := token.Verify(encoded, resolver, &noopRevocationChecker{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.AgentID != agentID {
		t.Fatalf("expected AgentID=%s, got %s", agentID, verified.AgentID)
	}
	if verified.ChainDepth != 1 {
		t.Fatalf("expected ChainDepth=1, got %d", verified.ChainDepth)
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	ks := newRootKeyStore(t)
	act, _ := token.IssueRootToken("agent://tamper", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())

	// Tamper with signature.
	act.Blocks[0].Signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	encoded, _ := token.Encode(act)

	resolver := &staticKeyResolver{
		keys: map[string]string{
			ks.KeyID(): agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
		},
	}
	_, err := token.Verify(encoded, resolver, &noopRevocationChecker{})
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	ks := newRootKeyStore(t)
	act, err := token.IssueRootToken("agent://expired", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())
	if err != nil {
		t.Fatalf("IssueRootToken: %v", err)
	}
	// Force expiry into the past.
	act.Blocks[0].Conditions.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	encoded, _ := token.Encode(act)

	resolver := &staticKeyResolver{
		keys: map[string]string{
			ks.KeyID(): agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
		},
	}
	_, err = token.Verify(encoded, resolver, &noopRevocationChecker{})
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

// revokedChecker always considers a specific token revoked.
type revokedChecker struct{ revokedTokenID string }

func (r *revokedChecker) IsTokenRevoked(id string) (bool, error) { return id == r.revokedTokenID, nil }
func (r *revokedChecker) IsAgentRevoked(_ string) (bool, error)  { return false, nil }

func TestVerify_RevokedToken(t *testing.T) {
	ks := newRootKeyStore(t)
	act, _ := token.IssueRootToken("agent://revoked", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())
	encoded, _ := token.Encode(act)

	resolver := &staticKeyResolver{
		keys: map[string]string{
			ks.KeyID(): agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
		},
	}
	_, err := token.Verify(encoded, resolver, &revokedChecker{revokedTokenID: act.TokenID})
	if err == nil {
		t.Fatal("expected error for revoked token")
	}
}

// --- Delegate ---

func TestDelegate_CapabilitySubset(t *testing.T) {
	ks := newRootKeyStore(t)
	agentKP := newKeyPair(t)

	parentACT, _ := token.IssueRootToken("agent://parent", []string{"read", "write", "execute"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())

	child, err := token.Delegate(parentACT, "agent://child", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(1800),
	}, agentKP.PrivateKey)
	if err != nil {
		t.Fatalf("Delegate: %v", err)
	}
	if len(child.Blocks) != 2 {
		t.Fatalf("expected 2 blocks, got %d", len(child.Blocks))
	}
	if child.Blocks[1].Subject != "agent://child" {
		t.Fatalf("expected subject=agent://child, got %s", child.Blocks[1].Subject)
	}
}

func TestDelegate_CapabilityAmplificationDenied(t *testing.T) {
	ks := newRootKeyStore(t)
	agentKP := newKeyPair(t)

	parentACT, _ := token.IssueRootToken("agent://parent", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())

	_, err := token.Delegate(parentACT, "agent://child", []string{"write"}, token.BlockConditions{
		ExpiresAt: futureExp(1800),
	}, agentKP.PrivateKey)
	if err == nil {
		t.Fatal("expected capability amplification error")
	}
}

func TestDelegate_ExpiryMonotonicity(t *testing.T) {
	ks := newRootKeyStore(t)
	agentKP := newKeyPair(t)

	parentACT, _ := token.IssueRootToken("agent://parent", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(1800),
	}, ks.PrivateKey())

	// Try to delegate with longer TTL than parent.
	_, err := token.Delegate(parentACT, "agent://child", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(7200), // longer than parent
	}, agentKP.PrivateKey)
	if err == nil {
		t.Fatal("expected expiry monotonicity error")
	}
}

func TestDelegate_MaxDelegationsEnforced(t *testing.T) {
	ks := newRootKeyStore(t)
	agentKP := newKeyPair(t)

	parentACT, _ := token.IssueRootToken("agent://parent", []string{"read"}, token.BlockConditions{
		ExpiresAt:      futureExp(3600),
		MaxDelegations: 1, // only 1 level of delegation allowed
	}, ks.PrivateKey())

	// First delegation should succeed.
	child, err := token.Delegate(parentACT, "agent://child", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(1800),
	}, agentKP.PrivateKey)
	if err != nil {
		t.Fatalf("first Delegate: %v", err)
	}

	// Second delegation should exceed max.
	grandchildKP := newKeyPair(t)
	_, err = token.Delegate(child, "agent://grandchild", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(900),
	}, grandchildKP.PrivateKey)
	if err == nil {
		t.Fatal("expected max delegation depth error")
	}
}

func TestDelegate_FullChainVerification(t *testing.T) {
	ks := newRootKeyStore(t)
	parentKP := newKeyPair(t)
	childKP := newKeyPair(t)

	parentACT, _ := token.IssueRootToken("agent://parent", []string{"read", "write"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())

	// parent → child.
	childACT, err := token.Delegate(parentACT, "agent://child", []string{"read", "write"}, token.BlockConditions{
		ExpiresAt: futureExp(1800),
	}, parentKP.PrivateKey)
	if err != nil {
		t.Fatalf("Delegate parent→child: %v", err)
	}

	// child → grandchild (only "read").
	grandchildACT, err := token.Delegate(childACT, "agent://grandchild", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(900),
	}, childKP.PrivateKey)
	if err != nil {
		t.Fatalf("Delegate child→grandchild: %v", err)
	}

	encoded, _ := token.Encode(grandchildACT)

	resolver := &staticKeyResolver{
		keys: map[string]string{
			ks.KeyID():       agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
			parentKP.KeyID:   agcrypto.EncodePublicKeyBase64(parentKP.PublicKey),
			childKP.KeyID:    agcrypto.EncodePublicKeyBase64(childKP.PublicKey),
		},
	}

	verified, err := token.Verify(encoded, resolver, &noopRevocationChecker{})
	if err != nil {
		t.Fatalf("Verify 3-hop chain: %v", err)
	}
	if verified.ChainDepth != 3 {
		t.Fatalf("expected ChainDepth=3, got %d", verified.ChainDepth)
	}
	if verified.AgentID != "agent://grandchild" {
		t.Fatalf("expected AgentID=agent://grandchild, got %s", verified.AgentID)
	}
	// Effective caps should be intersection: "read" only.
	if len(verified.Capabilities) != 1 || verified.Capabilities[0] != "read" {
		t.Fatalf("expected capabilities=[read], got %v", verified.Capabilities)
	}
}

// --- Additional helpers for new tests ---

type agentRevokedChecker struct{ revokedAgentID string }

func (r *agentRevokedChecker) IsTokenRevoked(_ string) (bool, error) { return false, nil }
func (r *agentRevokedChecker) IsAgentRevoked(id string) (bool, error) {
	return id == r.revokedAgentID, nil
}

type errorChecker struct{}

func (e *errorChecker) IsTokenRevoked(_ string) (bool, error) { return false, fmt.Errorf("db error") }
func (e *errorChecker) IsAgentRevoked(_ string) (bool, error)  { return false, nil }

// --- TestIssueRootTokenWithOptions ---

func TestIssueRootTokenWithOptions(t *testing.T) {
	ks := newRootKeyStore(t)
	opts := token.RootTokenOptions{
		UserID:           "user-abc",
		SystemPromptHash: "sha256-xyz",
		ToolFingerprint:  "fp-123",
	}
	act, err := token.IssueRootTokenWithOptions("agent://opts-agent", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey(), opts)
	if err != nil {
		t.Fatalf("IssueRootTokenWithOptions: %v", err)
	}
	if len(act.Blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(act.Blocks))
	}
	block := act.Blocks[0]
	if block.UserID != "user-abc" {
		t.Fatalf("expected UserID=user-abc, got %q", block.UserID)
	}
	if block.SystemPromptHash != "sha256-xyz" {
		t.Fatalf("expected SystemPromptHash=sha256-xyz, got %q", block.SystemPromptHash)
	}
	if block.ToolFingerprint != "fp-123" {
		t.Fatalf("expected ToolFingerprint=fp-123, got %q", block.ToolFingerprint)
	}
}

// --- TestVerify_UnsupportedVersion ---

func TestVerify_UnsupportedVersion(t *testing.T) {
	ks := newRootKeyStore(t)
	act, _ := token.IssueRootToken("agent://v2", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())

	act.Version = 2
	encoded, _ := token.Encode(act)

	resolver := &staticKeyResolver{keys: map[string]string{
		ks.KeyID(): agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
	}}
	_, err := token.Verify(encoded, resolver, &noopRevocationChecker{})
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

// --- TestVerify_NoBlocks ---

func TestVerify_NoBlocks(t *testing.T) {
	ks := newRootKeyStore(t)
	act, _ := token.IssueRootToken("agent://noblocks", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())

	act.Blocks = []token.Block{}
	encoded, _ := token.Encode(act)

	resolver := &staticKeyResolver{keys: map[string]string{
		ks.KeyID(): agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
	}}
	_, err := token.Verify(encoded, resolver, &noopRevocationChecker{})
	if err == nil {
		t.Fatal("expected error for empty blocks")
	}
}

// --- TestVerify_BlockIndexMismatch ---

func TestVerify_BlockIndexMismatch(t *testing.T) {
	ks := newRootKeyStore(t)
	act, _ := token.IssueRootToken("agent://idx", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())

	act.Blocks[0].Index = 99
	encoded, _ := token.Encode(act)

	resolver := &staticKeyResolver{keys: map[string]string{
		ks.KeyID(): agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
	}}
	_, err := token.Verify(encoded, resolver, &noopRevocationChecker{})
	if err == nil {
		t.Fatal("expected error for block index mismatch")
	}
}

// --- TestVerify_ChainLinkageBroken ---

func TestVerify_ChainLinkageBroken(t *testing.T) {
	ks := newRootKeyStore(t)
	agentKP := newKeyPair(t)

	parentACT, _ := token.IssueRootToken("agent://parent", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())

	childACT, _ := token.Delegate(parentACT, "agent://child", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(1800),
	}, agentKP.PrivateKey)

	// Break the chain linkage: set block[1].Issuer to something that doesn't match block[0].Subject.
	childACT.Blocks[1].Issuer = "agent://nobody"
	encoded, _ := token.Encode(childACT)

	resolver := &staticKeyResolver{keys: map[string]string{
		ks.KeyID():     agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
		agentKP.KeyID: agcrypto.EncodePublicKeyBase64(agentKP.PublicKey),
	}}
	_, err := token.Verify(encoded, resolver, &noopRevocationChecker{})
	if err == nil {
		t.Fatal("expected error for broken chain linkage")
	}
}

// --- TestVerify_AgentRevoked ---

func TestVerify_AgentRevoked(t *testing.T) {
	ks := newRootKeyStore(t)
	agentID := "agent://revoked-agent"
	act, _ := token.IssueRootToken(agentID, []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())
	encoded, _ := token.Encode(act)

	resolver := &staticKeyResolver{keys: map[string]string{
		ks.KeyID(): agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
	}}
	_, err := token.Verify(encoded, resolver, &agentRevokedChecker{revokedAgentID: agentID})
	if err == nil {
		t.Fatal("expected error for revoked agent")
	}
	if !containsStr(err.Error(), "revoked") {
		t.Fatalf("expected error containing 'revoked', got: %v", err)
	}
}

// --- TestVerify_IssuerRevoked ---

func TestVerify_IssuerRevoked(t *testing.T) {
	ks := newRootKeyStore(t)
	agentKP := newKeyPair(t)

	parentACT, _ := token.IssueRootToken("agent://parent", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())

	childACT, _ := token.Delegate(parentACT, "agent://child", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(1800),
	}, agentKP.PrivateKey)
	encoded, _ := token.Encode(childACT)

	resolver := &staticKeyResolver{keys: map[string]string{
		ks.KeyID():     agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
		agentKP.KeyID: agcrypto.EncodePublicKeyBase64(agentKP.PublicKey),
	}}
	// Revoke the issuer of block[1], which is "agent://parent" (block[0].Subject).
	_, err := token.Verify(encoded, resolver, &agentRevokedChecker{revokedAgentID: "agent://parent"})
	if err == nil {
		t.Fatal("expected error for revoked issuer")
	}
	if !containsStr(err.Error(), "revoked") {
		t.Fatalf("expected error containing 'revoked', got: %v", err)
	}
}

// --- TestVerify_NotBefore ---

func TestVerify_NotBefore(t *testing.T) {
	ks := newRootKeyStore(t)
	act, _ := token.IssueRootToken("agent://nbf", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())

	// Set NotBefore to far in the future.
	act.Blocks[0].Conditions.NotBefore = futureExp(9999)
	encoded, _ := token.Encode(act)

	resolver := &staticKeyResolver{keys: map[string]string{
		ks.KeyID(): agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
	}}
	_, err := token.Verify(encoded, resolver, &noopRevocationChecker{})
	if err == nil {
		t.Fatal("expected error for not-yet-valid token")
	}
	if !containsStr(err.Error(), "not yet valid") {
		t.Fatalf("expected error containing 'not yet valid', got: %v", err)
	}
}

// --- TestVerify_RevocationCheckerError ---

func TestVerify_RevocationCheckerError(t *testing.T) {
	ks := newRootKeyStore(t)
	act, _ := token.IssueRootToken("agent://checker-err", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())
	encoded, _ := token.Encode(act)

	resolver := &staticKeyResolver{keys: map[string]string{
		ks.KeyID(): agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
	}}
	_, err := token.Verify(encoded, resolver, &errorChecker{})
	if err == nil {
		t.Fatal("expected error from revocation checker")
	}
}

// --- TestVerify_CapabilityAmplificationInChain ---

func TestVerify_CapabilityAmplificationInChain(t *testing.T) {
	ks := newRootKeyStore(t)
	agentKP := newKeyPair(t)

	parentACT, _ := token.IssueRootToken("agent://parent", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())

	childACT, _ := token.Delegate(parentACT, "agent://child", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(1800),
	}, agentKP.PrivateKey)

	// Manually amplify capabilities in block[1] after signing.
	childACT.Blocks[1].Capabilities = []string{"read", "write"}
	encoded, _ := token.Encode(childACT)

	resolver := &staticKeyResolver{keys: map[string]string{
		ks.KeyID():     agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
		agentKP.KeyID: agcrypto.EncodePublicKeyBase64(agentKP.PublicKey),
	}}
	_, err := token.Verify(encoded, resolver, &noopRevocationChecker{})
	if err == nil {
		t.Fatal("expected error for capability amplification in chain")
	}
}

// --- TestVerify_ExpiryMonotonicityViolation ---

func TestVerify_ExpiryMonotonicityViolation(t *testing.T) {
	ks := newRootKeyStore(t)
	agentKP := newKeyPair(t)

	parentACT, _ := token.IssueRootToken("agent://parent", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(1800),
	}, ks.PrivateKey())

	childACT, _ := token.Delegate(parentACT, "agent://child", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(900),
	}, agentKP.PrivateKey)

	// Manually set block[1] expiry to exceed block[0] expiry.
	childACT.Blocks[1].Conditions.ExpiresAt = futureExp(7200)
	encoded, _ := token.Encode(childACT)

	resolver := &staticKeyResolver{keys: map[string]string{
		ks.KeyID():     agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
		agentKP.KeyID: agcrypto.EncodePublicKeyBase64(agentKP.PublicKey),
	}}
	_, err := token.Verify(encoded, resolver, &noopRevocationChecker{})
	if err == nil {
		t.Fatal("expected error for expiry monotonicity violation in chain")
	}
}

// --- TestVerify_ExpiresAtZeroBlocked ---

func TestVerify_ExpiresAtZeroBlocked(t *testing.T) {
	ks := newRootKeyStore(t)
	act, _ := token.IssueRootToken("agent://zeroexp", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())

	// Force ExpiresAt to zero as a bypass attempt.
	act.Blocks[0].Conditions.ExpiresAt = 0
	encoded, _ := token.Encode(act)

	resolver := &staticKeyResolver{keys: map[string]string{
		ks.KeyID(): agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
	}}
	_, err := token.Verify(encoded, resolver, &noopRevocationChecker{})
	if err == nil {
		t.Fatal("expected error for zero ExpiresAt")
	}
	if !containsStr(err.Error(), "missing expiry") {
		t.Fatalf("expected error containing 'missing expiry', got: %v", err)
	}
}

// --- TestDecode_ValidBase64InvalidJSON ---

func TestDecode_ValidBase64InvalidJSON(t *testing.T) {
	// base64url-encode bytes that are not valid JSON.
	invalidJSON := []byte("{not valid json}")
	encoded := base64.RawURLEncoding.EncodeToString(invalidJSON)

	_, err := token.Decode(encoded)
	if err == nil {
		t.Fatal("expected error for valid base64 containing invalid JSON")
	}
}

// --- TestDelegate_NilParent ---

func TestDelegate_NilParent(t *testing.T) {
	agentKP := newKeyPair(t)
	_, err := token.Delegate(nil, "agent://child", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(1800),
	}, agentKP.PrivateKey)
	if err == nil {
		t.Fatal("expected error for nil parent")
	}
}

// --- TestDelegate_ZeroExpiry ---

func TestDelegate_ZeroExpiry(t *testing.T) {
	ks := newRootKeyStore(t)
	agentKP := newKeyPair(t)

	parentACT, _ := token.IssueRootToken("agent://parent", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())

	_, err := token.Delegate(parentACT, "agent://child", []string{"read"}, token.BlockConditions{
		ExpiresAt: 0,
	}, agentKP.PrivateKey)
	if err == nil {
		t.Fatal("expected error for zero expiry in Delegate")
	}
}

// --- TestVerify_UserIDPropagated ---

func TestVerify_UserIDPropagated(t *testing.T) {
	ks := newRootKeyStore(t)
	opts := token.RootTokenOptions{UserID: "user-123"}
	act, err := token.IssueRootTokenWithOptions("agent://uid-agent", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey(), opts)
	if err != nil {
		t.Fatalf("IssueRootTokenWithOptions: %v", err)
	}
	encoded, _ := token.Encode(act)

	resolver := &staticKeyResolver{keys: map[string]string{
		ks.KeyID(): agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
	}}
	verified, err := token.Verify(encoded, resolver, &noopRevocationChecker{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.UserID != "user-123" {
		t.Fatalf("expected UserID=user-123, got %q", verified.UserID)
	}
}

// --- TestVerify_NilRevocationChecker ---

func TestVerify_NilRevocationChecker(t *testing.T) {
	ks := newRootKeyStore(t)
	act, _ := token.IssueRootToken("agent://nil-checker", []string{"read"}, token.BlockConditions{
		ExpiresAt: futureExp(3600),
	}, ks.PrivateKey())
	encoded, _ := token.Encode(act)

	resolver := &staticKeyResolver{keys: map[string]string{
		ks.KeyID(): agcrypto.EncodePublicKeyBase64(ks.PublicKey()),
	}}
	// nil revocationChecker should be accepted without panic.
	verified, err := token.Verify(encoded, resolver, nil)
	if err != nil {
		t.Fatalf("Verify with nil revocation checker: %v", err)
	}
	if verified.AgentID != "agent://nil-checker" {
		t.Fatalf("expected AgentID=agent://nil-checker, got %s", verified.AgentID)
	}
}

// containsStr is a simple substring check helper for test assertions.
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}

