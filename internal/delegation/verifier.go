package delegation

import (
	"container/list"
	"fmt"
	"sync"

	"github.com/agentity/agentity/internal/identity"
	agcrypto "github.com/agentity/agentity/pkg/crypto"
)

const maxKeyCacheSize = 10_000

// lruEntry is a single entry in the LRU cache.
type lruEntry struct {
	keyID  string
	pubKey string
}

// KeyResolverImpl resolves key IDs to base64url-encoded public keys.
// M5 fix: uses GetAgentByKeyID (O(1) indexed lookup) instead of ListAgents scan.
// The in-memory LRU cache (max 10,000 entries) avoids repeated store lookups
// for hot paths while preventing unbounded memory growth.
type KeyResolverImpl struct {
	rootKeyStore  *agcrypto.RootKeyStore
	identityStore identity.Store
	mu            sync.Mutex
	cache         map[string]*list.Element // keyID → list element
	lruList       *list.List               // front = most recently used
}

// NewKeyResolver creates a new key resolver.
func NewKeyResolver(rootKeyStore *agcrypto.RootKeyStore, identityStore identity.Store) *KeyResolverImpl {
	return &KeyResolverImpl{
		rootKeyStore:  rootKeyStore,
		identityStore: identityStore,
		cache:         make(map[string]*list.Element),
		lruList:       list.New(),
	}
}

// ResolveKey returns the base64url-encoded public key for the given key ID.
func (r *KeyResolverImpl) ResolveKey(keyID string) (string, error) {
	// Root key is checked first — no store round-trip needed.
	if keyID == r.rootKeyStore.KeyID() {
		return agcrypto.EncodePublicKeyBase64(r.rootKeyStore.PublicKey()), nil
	}

	r.mu.Lock()
	if elem, ok := r.cache[keyID]; ok {
		r.lruList.MoveToFront(elem)
		pubKey := elem.Value.(*lruEntry).pubKey
		r.mu.Unlock()
		return pubKey, nil
	}
	r.mu.Unlock()

	// O(1) indexed lookup — no table scan, no artificial agent limit.
	agent, err := r.identityStore.GetAgentByKeyID(keyID)
	if err != nil {
		return "", &KeyNotFoundError{KeyID: keyID}
	}

	r.mu.Lock()
	r.insertLocked(keyID, agent.PublicKey)
	r.mu.Unlock()

	return agent.PublicKey, nil
}

// insertLocked adds an entry to the LRU cache, evicting the LRU entry when full.
// Must be called with r.mu held.
func (r *KeyResolverImpl) insertLocked(keyID, pubKey string) {
	if elem, ok := r.cache[keyID]; ok {
		// Update existing entry and move to front.
		elem.Value.(*lruEntry).pubKey = pubKey
		r.lruList.MoveToFront(elem)
		return
	}
	// Evict least-recently-used entry if at capacity.
	if r.lruList.Len() >= maxKeyCacheSize {
		oldest := r.lruList.Back()
		if oldest != nil {
			r.lruList.Remove(oldest)
			delete(r.cache, oldest.Value.(*lruEntry).keyID)
		}
	}
	elem := r.lruList.PushFront(&lruEntry{keyID: keyID, pubKey: pubKey})
	r.cache[keyID] = elem
}

// InvalidateCache removes a key ID from the cache.
// Must be called by RotateKey so that post-rotation verifications resolve the new key.
func (r *KeyResolverImpl) InvalidateCache(keyID string) {
	r.mu.Lock()
	if elem, ok := r.cache[keyID]; ok {
		r.lruList.Remove(elem)
		delete(r.cache, keyID)
	}
	r.mu.Unlock()
}

// KeyNotFoundError indicates a key ID could not be resolved.
type KeyNotFoundError struct {
	KeyID string
}

func (e *KeyNotFoundError) Error() string {
	return fmt.Sprintf("key not found: %s", e.KeyID)
}
