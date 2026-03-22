package vault_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/agentity/agentity/internal/vault"
)

// newTestEncryptor creates a LocalEncryptor with a fixed 32-byte test key.
func newTestEncryptor(t *testing.T) *vault.LocalEncryptor {
	t.Helper()
	key := bytes.Repeat([]byte{0xAB}, 32)
	enc, err := vault.NewLocalEncryptor(key)
	if err != nil {
		t.Fatalf("NewLocalEncryptor: %v", err)
	}
	return enc
}

func TestLocalEncryptor_RoundTrip(t *testing.T) {
	enc := newTestEncryptor(t)
	plaintext := []byte("super-secret-value")

	ciphertext, iv, keyVersion, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := enc.Decrypt(ciphertext, iv, keyVersion)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestLocalEncryptor_DifferentIVEachTime(t *testing.T) {
	enc := newTestEncryptor(t)
	plaintext := []byte("same-plaintext")

	ct1, iv1, _, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}
	ct2, iv2, _, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}

	if bytes.Equal(iv1, iv2) {
		t.Error("expected different IVs for each encryption, got identical IVs")
	}
	if bytes.Equal(ct1, ct2) {
		t.Error("expected different ciphertexts for each encryption, got identical ciphertexts")
	}
}

func TestLocalEncryptor_BadKeySize(t *testing.T) {
	_, err := vault.NewLocalEncryptor([]byte("tooshort"))
	if err == nil {
		t.Error("expected error for short key, got nil")
	}
}

func TestVaultService_PutGetDelete(t *testing.T) {
	enc := newTestEncryptor(t)
	store := vault.NewMemoryVaultStore()
	svc := vault.NewVaultService(store, enc)

	ctx := context.Background()
	agentID := "agent-123"

	if err := svc.Put(ctx, agentID, "API_KEY", "my-secret"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	val, err := svc.Get(ctx, agentID, "API_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "my-secret" {
		t.Errorf("Get returned %q, want %q", val, "my-secret")
	}

	if err := svc.Delete(ctx, agentID, "API_KEY"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = svc.Get(ctx, agentID, "API_KEY")
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}

func TestVaultService_List(t *testing.T) {
	enc := newTestEncryptor(t)
	store := vault.NewMemoryVaultStore()
	svc := vault.NewVaultService(store, enc)

	ctx := context.Background()
	agentID := "agent-list"

	keys := []string{"AWS_SECRET", "OPENAI_API_KEY", "STRIPE_KEY"}
	for _, k := range keys {
		if err := svc.Put(ctx, agentID, k, "value-"+k); err != nil {
			t.Fatalf("Put %s: %v", k, err)
		}
	}

	listed, err := svc.List(ctx, agentID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != len(keys) {
		t.Errorf("List returned %d keys, want %d", len(listed), len(keys))
	}
	// MemoryVaultStore returns sorted keys.
	wantSorted := []string{"AWS_SECRET", "OPENAI_API_KEY", "STRIPE_KEY"}
	for i, k := range wantSorted {
		if i >= len(listed) || listed[i] != k {
			t.Errorf("listed[%d] = %q, want %q", i, listed[i], k)
		}
	}
}

func TestVaultService_GetNotFound(t *testing.T) {
	enc := newTestEncryptor(t)
	store := vault.NewMemoryVaultStore()
	svc := vault.NewVaultService(store, enc)

	ctx := context.Background()
	_, err := svc.Get(ctx, "no-such-agent", "NO_SUCH_KEY")
	if err == nil {
		t.Error("expected error for missing credential, got nil")
	}
}
