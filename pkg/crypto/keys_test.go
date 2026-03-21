package crypto_test

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/agentity/agentity/pkg/crypto"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if kp.PrivateKey == nil {
		t.Fatal("expected non-nil PrivateKey")
	}
	if kp.PublicKey == nil {
		t.Fatal("expected non-nil PublicKey")
	}
	if kp.KeyID == "" {
		t.Fatal("expected non-empty KeyID")
	}
	if len(kp.PrivateKey) != ed25519.PrivateKeySize {
		t.Fatalf("expected PrivateKey size %d, got %d", ed25519.PrivateKeySize, len(kp.PrivateKey))
	}
	if len(kp.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("expected PublicKey size %d, got %d", ed25519.PublicKeySize, len(kp.PublicKey))
	}
}

func TestGenerateKeyPairUniqueness(t *testing.T) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	if kp1.KeyID == kp2.KeyID {
		t.Fatal("two generated key pairs should have different KeyIDs")
	}
}

func TestComputeKeyID(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	kid := crypto.ComputeKeyID(kp.PublicKey)
	if kid == "" {
		t.Fatal("expected non-empty key ID")
	}
	// Should be deterministic.
	if crypto.ComputeKeyID(kp.PublicKey) != kid {
		t.Fatal("ComputeKeyID is not deterministic")
	}
	// Should be base64url (no padding, no +/).
	if strings.Contains(kid, "=") || strings.Contains(kid, "+") || strings.Contains(kid, "/") {
		t.Fatalf("KeyID should be base64url encoded, got: %s", kid)
	}
}

func TestMarshalParsePrivateKeyPEM(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	pem, err := crypto.MarshalPrivateKeyPEM(kp.PrivateKey)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyPEM: %v", err)
	}
	if len(pem) == 0 {
		t.Fatal("expected non-empty PEM")
	}

	parsed, err := crypto.ParsePrivateKeyPEM(pem)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM: %v", err)
	}
	if !parsed.Equal(kp.PrivateKey) {
		t.Fatal("parsed private key does not match original")
	}
}

func TestMarshalParsePublicKeyPEM(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	pem, err := crypto.MarshalPublicKeyPEM(kp.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPublicKeyPEM: %v", err)
	}

	parsed, err := crypto.ParsePublicKeyPEM(pem)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM: %v", err)
	}
	if !parsed.Equal(kp.PublicKey) {
		t.Fatal("parsed public key does not match original")
	}
}

func TestParsePrivateKeyPEM_InvalidInput(t *testing.T) {
	_, err := crypto.ParsePrivateKeyPEM([]byte("not-a-pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM input")
	}
}

func TestParsePublicKeyPEM_InvalidInput(t *testing.T) {
	_, err := crypto.ParsePublicKeyPEM([]byte("garbage"))
	if err == nil {
		t.Fatal("expected error for invalid PEM input")
	}
}

func TestEncodeDecodePublicKeyBase64(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	encoded := crypto.EncodePublicKeyBase64(kp.PublicKey)
	if encoded == "" {
		t.Fatal("expected non-empty encoded key")
	}

	decoded, err := crypto.DecodePublicKeyBase64(encoded)
	if err != nil {
		t.Fatalf("DecodePublicKeyBase64: %v", err)
	}
	if !decoded.Equal(kp.PublicKey) {
		t.Fatal("decoded public key does not match original")
	}
}

func TestDecodePublicKeyBase64_InvalidLength(t *testing.T) {
	_, err := crypto.DecodePublicKeyBase64("dG9vLXNob3J0")
	if err == nil {
		t.Fatal("expected error for wrong-length key")
	}
}

func TestEncodeDecodePrivateKeyBase64(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	encoded := crypto.EncodePrivateKeyBase64(kp.PrivateKey)
	decoded, err := crypto.DecodePrivateKeyBase64(encoded)
	if err != nil {
		t.Fatalf("DecodePrivateKeyBase64: %v", err)
	}
	if !decoded.Equal(kp.PrivateKey) {
		t.Fatal("decoded private key does not match original")
	}
}

func TestRootKeyStore(t *testing.T) {
	store, err := crypto.NewRootKeyStore()
	if err != nil {
		t.Fatalf("NewRootKeyStore: %v", err)
	}
	if store.KeyID() == "" {
		t.Fatal("expected non-empty key ID")
	}
	if store.PublicKey() == nil {
		t.Fatal("expected non-nil public key")
	}
	if store.PrivateKey() == nil {
		t.Fatal("expected non-nil private key")
	}
}

func TestRootKeyStore_Rotate(t *testing.T) {
	store, _ := crypto.NewRootKeyStore()
	originalKID := store.KeyID()

	newKID, err := store.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newKID == originalKID {
		t.Fatal("expected key ID to change after rotation")
	}
	if store.KeyID() != newKID {
		t.Fatal("store.KeyID() should return the new key ID after rotation")
	}
}

func TestNewRootKeyStoreFromKey(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	store := crypto.NewRootKeyStoreFromKey(kp.PrivateKey)
	if store.KeyID() != kp.KeyID {
		t.Fatalf("expected KeyID=%s, got %s", kp.KeyID, store.KeyID())
	}
	if !store.PublicKey().Equal(kp.PublicKey) {
		t.Fatal("public key mismatch")
	}
}
