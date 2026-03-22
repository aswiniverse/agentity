package delegation_test

import (
	"testing"
	"time"

	"github.com/agentity/agentity/internal/delegation"
	"github.com/agentity/agentity/internal/identity"
	"github.com/agentity/agentity/internal/store"
	agcrypto "github.com/agentity/agentity/pkg/crypto"
)

func newAgent(id, keyID, pubKey string) *identity.AgentIdentity {
	return &identity.AgentIdentity{
		ID:        id,
		Name:      "test",
		PublicKey: pubKey,
		KeyID:     keyID,
		Status:    identity.AgentStatusActive,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

func newRootKeyStore(t *testing.T) *agcrypto.RootKeyStore {
	t.Helper()
	ks, err := agcrypto.NewRootKeyStore()
	if err != nil {
		t.Fatalf("NewRootKeyStore: %v", err)
	}
	return ks
}

func TestKeyResolver_RootKeyResolved(t *testing.T) {
	ks := newRootKeyStore(t)
	s := store.NewMemoryStore()
	r := delegation.NewKeyResolver(ks, s)

	got, err := r.ResolveKey(ks.KeyID())
	if err != nil {
		t.Fatalf("ResolveKey root: %v", err)
	}
	want := agcrypto.EncodePublicKeyBase64(ks.PublicKey())
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestKeyResolver_AgentKeyResolvedFromStore(t *testing.T) {
	ks := newRootKeyStore(t)
	s := store.NewMemoryStore()
	r := delegation.NewKeyResolver(ks, s)

	kp, err := agcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pubKey := agcrypto.EncodePublicKeyBase64(kp.PublicKey)
	agent := newAgent("agent://test", kp.KeyID, pubKey)
	if err := s.CreateAgent(agent); err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	got, err := r.ResolveKey(kp.KeyID)
	if err != nil {
		t.Fatalf("ResolveKey: %v", err)
	}
	if got != pubKey {
		t.Fatalf("expected %s, got %s", pubKey, got)
	}
}

func TestKeyResolver_CacheHitAvoidsStoreOnSecondCall(t *testing.T) {
	ks := newRootKeyStore(t)
	s := store.NewMemoryStore()
	r := delegation.NewKeyResolver(ks, s)

	kp, _ := agcrypto.GenerateKeyPair()
	pubKey := agcrypto.EncodePublicKeyBase64(kp.PublicKey)
	agent := newAgent("agent://cache", kp.KeyID, pubKey)
	_ = s.CreateAgent(agent)

	// First call populates cache.
	first, err := r.ResolveKey(kp.KeyID)
	if err != nil || first != pubKey {
		t.Fatalf("first resolve: err=%v got=%s", err, first)
	}

	// Remove agent from store — second call must still succeed from cache.
	_ = s.DeleteAgent("agent://cache")
	second, err := r.ResolveKey(kp.KeyID)
	if err != nil {
		t.Fatalf("second resolve (from cache): %v", err)
	}
	if second != pubKey {
		t.Fatalf("cache returned wrong value: %s", second)
	}
}

func TestKeyResolver_InvalidateCacheForcesFreshLookup(t *testing.T) {
	ks := newRootKeyStore(t)
	s := store.NewMemoryStore()
	r := delegation.NewKeyResolver(ks, s)

	kp, _ := agcrypto.GenerateKeyPair()
	pubKey := agcrypto.EncodePublicKeyBase64(kp.PublicKey)
	agent := newAgent("agent://invalidate", kp.KeyID, pubKey)
	s.CreateAgent(agent)

	// Populate cache.
	_, _ = r.ResolveKey(kp.KeyID)

	// Delete agent from store then invalidate — next call should fail (not cached).
	_ = s.DeleteAgent("agent://invalidate")
	r.InvalidateCache(kp.KeyID)

	_, err := r.ResolveKey(kp.KeyID)
	if err == nil {
		t.Fatal("expected error after cache invalidation with missing agent")
	}
}

func TestKeyResolver_UnknownKeyReturnsError(t *testing.T) {
	ks := newRootKeyStore(t)
	s := store.NewMemoryStore()
	r := delegation.NewKeyResolver(ks, s)

	_, err := r.ResolveKey("not-a-real-key-id")
	if err == nil {
		t.Fatal("expected error for unknown key ID")
	}
}

func TestKeyResolver_KeyRotationUpdatesCache(t *testing.T) {
	ks := newRootKeyStore(t)
	s := store.NewMemoryStore()
	r := delegation.NewKeyResolver(ks, s)

	kp1, _ := agcrypto.GenerateKeyPair()
	pub1 := agcrypto.EncodePublicKeyBase64(kp1.PublicKey)
	agent := newAgent("agent://rotate", kp1.KeyID, pub1)
	s.CreateAgent(agent)

	// Resolve first key — populates cache.
	got, err := r.ResolveKey(kp1.KeyID)
	if err != nil || got != pub1 {
		t.Fatalf("initial resolve: err=%v got=%s", err, got)
	}

	// Simulate key rotation: update store with new key, invalidate old cache entry.
	kp2, _ := agcrypto.GenerateKeyPair()
	pub2 := agcrypto.EncodePublicKeyBase64(kp2.PublicKey)
	agent.KeyID = kp2.KeyID
	agent.PublicKey = pub2
	_ = s.UpdateAgent(agent)
	r.InvalidateCache(kp1.KeyID)

	// Old key ID should no longer resolve.
	_, err = r.ResolveKey(kp1.KeyID)
	if err == nil {
		t.Fatal("expected error for old key ID after rotation")
	}

	// New key ID should resolve correctly.
	got2, err := r.ResolveKey(kp2.KeyID)
	if err != nil {
		t.Fatalf("new key resolve: %v", err)
	}
	if got2 != pub2 {
		t.Fatalf("expected %s, got %s", pub2, got2)
	}
}
