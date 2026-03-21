package delegation

import (
	"sync"

	agcrypto "github.com/agentity/agentity/pkg/crypto"
	"github.com/agentity/agentity/internal/identity"
)

// KeyResolverImpl resolves key IDs to base64url-encoded public keys
// by looking up the identity store and the root key store.
type KeyResolverImpl struct {
	rootKeyStore  *agcrypto.RootKeyStore
	identityStore identity.Store
	mu            sync.RWMutex
	cache         map[string]string // keyID -> base64url public key
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
	// Check if it's the root key.
	if keyID == r.rootKeyStore.KeyID() {
		return agcrypto.EncodePublicKeyBase64(r.rootKeyStore.PublicKey()), nil
	}

	// Check cache.
	r.mu.RLock()
	if pubKey, ok := r.cache[keyID]; ok {
		r.mu.RUnlock()
		return pubKey, nil
	}
	r.mu.RUnlock()

	// Search through all agents (in production, you'd have a key_id index).
	agents, err := r.identityStore.ListAgents(identity.AgentFilter{Limit: 1000})
	if err != nil {
		return "", err
	}
	for _, agent := range agents {
		if agent.KeyID == keyID {
			r.mu.Lock()
			r.cache[keyID] = agent.PublicKey
			r.mu.Unlock()
			return agent.PublicKey, nil
		}
	}

	return "", &KeyNotFoundError{KeyID: keyID}
}

// InvalidateCache removes a key ID from the cache (used after key rotation).
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
	return "key not found: " + e.KeyID
}
