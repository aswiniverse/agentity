package vault

import (
	"context"
	"fmt"
)

// VaultService provides high-level credential management with transparent encryption.
type VaultService struct {
	store     VaultStore
	encryptor Encryptor
}

// NewVaultService creates a new VaultService.
func NewVaultService(store VaultStore, encryptor Encryptor) *VaultService {
	return &VaultService{store: store, encryptor: encryptor}
}

// Put encrypts value and stores it under agentID/key.
func (s *VaultService) Put(ctx context.Context, agentID, key, value string) error {
	ciphertext, iv, keyVersion, err := s.encryptor.Encrypt([]byte(value))
	if err != nil {
		return fmt.Errorf("encrypt credential: %w", err)
	}
	encoded := encryptedValueToString(ciphertext)
	return s.store.Put(ctx, agentID, key, encoded, iv, keyVersion)
}

// Get retrieves and decrypts the credential stored under agentID/key.
func (s *VaultService) Get(ctx context.Context, agentID, key string) (string, error) {
	encoded, iv, keyVersion, err := s.store.Get(ctx, agentID, key)
	if err != nil {
		return "", err
	}
	ciphertext, err := stringToEncryptedValue(encoded)
	if err != nil {
		return "", fmt.Errorf("decode encrypted value: %w", err)
	}
	plaintext, err := s.encryptor.Decrypt(ciphertext, iv, keyVersion)
	if err != nil {
		return "", fmt.Errorf("decrypt credential: %w", err)
	}
	return string(plaintext), nil
}

// Delete removes the credential stored under agentID/key.
func (s *VaultService) Delete(ctx context.Context, agentID, key string) error {
	return s.store.Delete(ctx, agentID, key)
}

// List returns all credential keys for the given agentID.
func (s *VaultService) List(ctx context.Context, agentID string) ([]string, error) {
	return s.store.List(ctx, agentID)
}
