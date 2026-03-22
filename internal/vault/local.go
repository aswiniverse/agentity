package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

const localKeyVersion = "local-v1"

// LocalEncryptor implements Encryptor using AES-256-GCM with a local key.
type LocalEncryptor struct {
	key []byte
}

// NewLocalEncryptor creates a LocalEncryptor from a 32-byte key.
// Returns an error if the key is not exactly 32 bytes.
func NewLocalEncryptor(key []byte) (*LocalEncryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("vault key must be 32 bytes, got %d", len(key))
	}
	keyCopy := make([]byte, 32)
	copy(keyCopy, key)
	return &LocalEncryptor{key: keyCopy}, nil
}

// NewLocalEncryptorFromEnv reads AGENTITY_VAULT_KEY (64 hex chars), hex-decodes it,
// and calls NewLocalEncryptor.
func NewLocalEncryptorFromEnv() (*LocalEncryptor, error) {
	hexKey := os.Getenv("AGENTITY_VAULT_KEY")
	if hexKey == "" {
		return nil, fmt.Errorf("AGENTITY_VAULT_KEY is not set")
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decode AGENTITY_VAULT_KEY: %w", err)
	}
	return NewLocalEncryptor(key)
}

// Encrypt encrypts plaintext using AES-256-GCM with a random 12-byte nonce.
// Returns ciphertext (sealed output), iv (the nonce), and keyVersion="local-v1".
func (e *LocalEncryptor) Encrypt(plaintext []byte) (ciphertext, iv []byte, keyVersion string, err error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, nil, "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, "", fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, "", fmt.Errorf("generate nonce: %w", err)
	}

	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	return sealed, nonce, localKeyVersion, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM with the given iv (nonce).
// keyVersion is accepted for future key rotation but currently only "local-v1" is supported.
func (e *LocalEncryptor) Decrypt(ciphertext, iv []byte, keyVersion string) ([]byte, error) {
	if keyVersion != localKeyVersion {
		return nil, fmt.Errorf("unsupported key version: %s", keyVersion)
	}
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}
