package vault

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"sync"
)

// VaultStore defines the persistence interface for encrypted credential storage.
type VaultStore interface {
	Put(ctx context.Context, agentID, key, encryptedValue string, iv []byte, keyVersion string) error
	Get(ctx context.Context, agentID, key string) (encryptedValue string, iv []byte, keyVersion string, err error)
	Delete(ctx context.Context, agentID, key string) error
	List(ctx context.Context, agentID string) ([]string, error)
}

type memEntry struct {
	encryptedValue string
	iv             []byte
	keyVersion     string
}

// MemoryVaultStore implements VaultStore with an in-memory map for testing.
type MemoryVaultStore struct {
	mu      sync.RWMutex
	entries map[string]memEntry // key: "agentID\x00key"
}

// NewMemoryVaultStore creates a new in-memory vault store.
func NewMemoryVaultStore() *MemoryVaultStore {
	return &MemoryVaultStore{
		entries: make(map[string]memEntry),
	}
}

func memKey(agentID, key string) string {
	return agentID + "\x00" + key
}

func (s *MemoryVaultStore) Put(_ context.Context, agentID, key, encryptedValue string, iv []byte, keyVersion string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)
	s.entries[memKey(agentID, key)] = memEntry{
		encryptedValue: encryptedValue,
		iv:             ivCopy,
		keyVersion:     keyVersion,
	}
	return nil
}

func (s *MemoryVaultStore) Get(_ context.Context, agentID, key string) (string, []byte, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[memKey(agentID, key)]
	if !ok {
		return "", nil, "", fmt.Errorf("credential not found: agent=%s key=%s", agentID, key)
	}
	ivCopy := make([]byte, len(e.iv))
	copy(ivCopy, e.iv)
	return e.encryptedValue, ivCopy, e.keyVersion, nil
}

func (s *MemoryVaultStore) Delete(_ context.Context, agentID, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := memKey(agentID, key)
	if _, ok := s.entries[k]; !ok {
		return fmt.Errorf("credential not found: agent=%s key=%s", agentID, key)
	}
	delete(s.entries, k)
	return nil
}

func (s *MemoryVaultStore) List(_ context.Context, agentID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	prefix := agentID + "\x00"
	var keys []string
	for k := range s.entries {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k[len(prefix):])
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// encryptedValueToString base64-encodes a byte slice for storage as a string.
func encryptedValueToString(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// stringToEncryptedValue base64-decodes a stored string back to bytes.
func stringToEncryptedValue(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
