package delegation

import (
	"fmt"
	"sync"

	agcrypto "github.com/agentity/agentity/pkg/crypto"
	"github.com/agentity/agentity/internal/identity"
)

// KeyResolverImpl resolves key IDs to base64url-encoded public keys.
// M5 fix: uses GetAgentByKeyID (O(1) indexed lookup) instead of ListAgents scan.
// The in-memory cache avoids repeated store lookups for hot paths.
type KeyResolverImpl struct {
	rootKeyStore  *agcrypto.RootKeyStore
	identityStore identity.Store
	mu            sync.RWMutex
	cache         map[string]string // keyID → base64url public key
}

// NewKeyResolver creates a new key resolver.
func NewKeyResolver(rootKeyStore *agcrypto.RootKeyStore, identityStore identity.Store) *KeyResolverImpl {
	return &KeyResolverImpl{
		rootKeyStore:  rootKeyStore,
		identityStore: identityStore,
		cache:         make(map[string]string),
	}
}

// ResolveKey returns the base64url-encoded public key for the given key ID.
func (r *KeyResolverImpl) ResolveKey(keyID string) (string, error) {
	// Root key is checked first — no store round-trip needed.
	if keyID == r.rootKeyStore.KeyID() {
		return agcrypto.EncodePublicKeyBase64(r.rootKeyStore.PublicKey()), nil
	}

	r.mu.RLock()
	if pubKey, ok := r.cache[keyID]; ok {
		r.mu.RUnlock()
		return pubKey, nil
	}
	r.mu.RUnlock()

	// O(1) indexed lookup — no table scan, no artificial agent limit.
	agent, err := r.identityStore.GetAgentByKeyID(keyID)
	if err != nil {
		return "", &KeyNotFoundError{KeyID: keyID}
	}

	r.mu.Lock()
	r.cache[keyID] = agent.PublicKey
	r.mu.Unlock()

	return agent.PublicKey, nil
}

// InvalidateCache removes a key ID from the cache.
// Must be called by RotateKey so that post-rotation verifications resolve the new key.
func (r *KeyResolverImpl) InvalidateCache(keyID string) {
	r.mu.Lock()
	delete(r.cache, keyID)
	r.mu.Unlock()
}

// KeyNotFoundError indicates a key ID could not be resolved.
type KeyNotFoundError struct {
	KeyID string
}

func (e *KeyNotFoundError) Error() string {
	return fmt.Sprintf("key not found: %s", e.KeyID)
}
