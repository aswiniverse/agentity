package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
)

// AgentKeyPair represents an agent's Ed25519 key pair.
type AgentKeyPair struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	KeyID      string
}

// GenerateKeyPair creates a new Ed25519 key pair and computes its KeyID.
func GenerateKeyPair() (*AgentKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	kid := ComputeKeyID(pub)
	return &AgentKeyPair{
		PrivateKey: priv,
		PublicKey:  pub,
		KeyID:      kid,
	}, nil
}

// ComputeKeyID returns the base64url-encoded SHA256 fingerprint of a public key.
func ComputeKeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// MarshalPrivateKeyPEM encodes an Ed25519 private key to PEM format.
func MarshalPrivateKeyPEM(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

// MarshalPublicKeyPEM encodes an Ed25519 public key to PEM format.
func MarshalPublicKeyPEM(key ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

// ParsePrivateKeyPEM decodes a PEM-encoded Ed25519 private key.
func ParsePrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519")
	}
	return edKey, nil
}

// ParsePublicKeyPEM decodes a PEM-encoded Ed25519 public key.
func ParsePublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519")
	}
	return edKey, nil
}

// EncodePublicKeyBase64 returns the base64url encoding of a raw Ed25519 public key.
func EncodePublicKeyBase64(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

// DecodePublicKeyBase64 decodes a base64url-encoded Ed25519 public key.
func DecodePublicKeyBase64(s string) (ed25519.PublicKey, error) {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(data) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: %d", len(data))
	}
	return ed25519.PublicKey(data), nil
}

// EncodePrivateKeyBase64 returns the base64url encoding of a raw Ed25519 private key.
func EncodePrivateKeyBase64(priv ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(priv)
}

// DecodePrivateKeyBase64 decodes a base64url-encoded Ed25519 private key.
func DecodePrivateKeyBase64(s string) (ed25519.PrivateKey, error) {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: %d", len(data))
	}
	return ed25519.PrivateKey(data), nil
}

// RootKeyStore holds the server's root signing key, thread-safe.
type RootKeyStore struct {
	mu      sync.RWMutex
	keyPair *AgentKeyPair
}

// NewRootKeyStore creates a new RootKeyStore with a freshly generated key pair.
func NewRootKeyStore() (*RootKeyStore, error) {
	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &RootKeyStore{keyPair: kp}, nil
}

// LoadOrCreateRootKeyStore loads the root key from keyFile if it exists, or
// generates a new one and persists it. This ensures token signatures survive
// server restarts (C5 fix).
func LoadOrCreateRootKeyStore(keyFile string) (*RootKeyStore, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	if err == nil {
		// File exists: load the key.
		priv, err := ParsePrivateKeyPEM(data)
		if err != nil {
			return nil, fmt.Errorf("parse root key PEM: %w", err)
		}
		return NewRootKeyStoreFromKey(priv), nil
	}

	// File doesn't exist: generate and persist.
	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}
	pem, err := MarshalPrivateKeyPEM(kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal root key: %w", err)
	}
	// Write with restrictive permissions (owner read/write only).
	if err := os.WriteFile(keyFile, pem, 0600); err != nil {
		return nil, fmt.Errorf("write key file %s: %w", keyFile, err)
	}
	return &RootKeyStore{keyPair: kp}, nil
}

// NewRootKeyStoreFromKey creates a RootKeyStore from an existing private key.
func NewRootKeyStoreFromKey(priv ed25519.PrivateKey) *RootKeyStore {
	pub := priv.Public().(ed25519.PublicKey)
	kid := ComputeKeyID(pub)
	return &RootKeyStore{
		keyPair: &AgentKeyPair{
			PrivateKey: priv,
			PublicKey:  pub,
			KeyID:      kid,
		},
	}
}

// PrivateKey returns the root private key.
func (r *RootKeyStore) PrivateKey() ed25519.PrivateKey {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.keyPair.PrivateKey
}

// PublicKey returns the root public key.
func (r *RootKeyStore) PublicKey() ed25519.PublicKey {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.keyPair.PublicKey
}

// KeyID returns the root key's ID.
func (r *RootKeyStore) KeyID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.keyPair.KeyID
}

// Rotate generates a new root key pair and returns the new key ID.
func (r *RootKeyStore) Rotate() (string, error) {
	kp, err := GenerateKeyPair()
	if err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keyPair = kp
	return kp.KeyID, nil
}
