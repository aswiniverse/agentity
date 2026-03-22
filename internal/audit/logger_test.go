package audit_test

import (
	"errors"
	"testing"
	"time"

	"github.com/agentity/agentity/internal/audit"
	agcrypto "github.com/agentity/agentity/pkg/crypto"
)

func newLogger(t *testing.T) *audit.Logger {
	t.Helper()
	ks, err := agcrypto.NewRootKeyStore()
	if err != nil {
		t.Fatalf("create root key store: %v", err)
	}
	return audit.NewLogger(ks.PrivateKey(), nil)
}

func newLoggerWithStore(t *testing.T, store audit.AuditStore) *audit.Logger {
	t.Helper()
	ks, err := agcrypto.NewRootKeyStore()
	if err != nil {
		t.Fatalf("create root key store: %v", err)
	}
	return audit.NewLogger(ks.PrivateKey(), store)
}

func TestAuditLogger_Log(t *testing.T) {
	l := newLogger(t)
	entry, err := l.Log(
		audit.EventTokenIssued,
		"agentity://server",
		"agent://test",
		"issue",
		"success",
		map[string]interface{}{"caps": []string{"read"}},
	)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}
	if entry.ID == "" {
		t.Fatal("expected non-empty entry ID")
	}
	if entry.Type != audit.EventTokenIssued {
		t.Fatalf("expected type=%s, got %s", audit.EventTokenIssued, entry.Type)
	}
	if entry.Signature == "" {
		t.Fatal("expected non-empty signature")
	}
}

func TestAuditLogger_LogWithToken(t *testing.T) {
	l := newLogger(t)
	entry, err := l.LogWithToken(
		audit.EventTokenDelegated,
		"agent://parent",
		"agent://child",
		"delegate",
		"token-id-123",
		"success",
		map[string]interface{}{"depth": 2},
	)
	if err != nil {
		t.Fatalf("LogWithToken: %v", err)
	}
	if entry.TokenID != "token-id-123" {
		t.Fatalf("expected token_id=token-id-123, got %s", entry.TokenID)
	}
}

func TestAuditLogger_Count(t *testing.T) {
	l := newLogger(t)
	if l.Count() != 0 {
		t.Fatal("expected count=0 on empty logger")
	}
	_, _ = l.Log(audit.EventTokenIssued, "a", "b", "issue", "success", nil)
	_, _ = l.Log(audit.EventTokenVerified, "a", "b", "verify", "success", nil)
	if l.Count() != 2 {
		t.Fatalf("expected count=2, got %d", l.Count())
	}
}

func TestAuditLogger_List(t *testing.T) {
	l := newLogger(t)
	for i := 0; i < 5; i++ {
		_, _ = l.Log(audit.EventTokenIssued, "a", "b", "issue", "success", nil)
	}
	entries := l.List(audit.AuditFilter{Limit: 3})
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries with limit=3, got %d", len(entries))
	}
	allEntries := l.List(audit.AuditFilter{Limit: 100})
	if len(allEntries) != 5 {
		t.Fatalf("expected all 5 entries, got %d", len(allEntries))
	}
}

func TestAuditLogger_ListOffset(t *testing.T) {
	l := newLogger(t)
	for i := 0; i < 5; i++ {
		_, _ = l.Log(audit.EventTokenIssued, "a", "b", "issue", "success", nil)
	}
	entries := l.List(audit.AuditFilter{Offset: 3, Limit: 10})
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries with offset=3, got %d", len(entries))
	}
}

func TestAuditLogger_SignatureNonEmpty(t *testing.T) {
	l := newLogger(t)
	entry, _ := l.Log(
		audit.EventAccessDenied,
		"agent://x",
		"agent://y",
		"verify",
		"denied",
		nil,
	)
	if entry.Signature == "" {
		t.Fatal("expected non-empty signature")
	}
	if len(entry.Signature) < 10 {
		t.Fatalf("signature too short: %s", entry.Signature)
	}
}

func TestAuditLogger_ConcurrentWrites(t *testing.T) {
	l := newLogger(t)
	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func() {
			_, _ = l.Log(audit.EventTokenIssued, "a", "b", "issue", "success", nil)
			done <- struct{}{}
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}
	if l.Count() != 20 {
		t.Fatalf("expected 20 entries after concurrent writes, got %d", l.Count())
	}
}

// TestAuditLogger_NilStore_InMemoryFallback verifies that when store is nil,
// in-memory log is used and List works correctly.
func TestAuditLogger_NilStore_InMemoryFallback(t *testing.T) {
	l := newLogger(t) // store=nil
	_, _ = l.Log(audit.EventTokenIssued, "actor-1", "target-1", "issue", "success", nil)
	_, _ = l.Log(audit.EventTokenVerified, "actor-2", "target-2", "verify", "success", nil)

	entries := l.List(audit.AuditFilter{Limit: 10})
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries from in-memory, got %d", len(entries))
	}
	if l.Count() != 2 {
		t.Fatalf("expected count=2, got %d", l.Count())
	}
}

// TestAuditLogger_WriteThrough verifies that entries are written to the store.
func TestAuditLogger_WriteThrough(t *testing.T) {
	ms := &mockStore{}
	l := newLoggerWithStore(t, ms)

	_, _ = l.Log(audit.EventTokenIssued, "actor-1", "target-1", "issue", "success", nil)

	// Give the goroutine time to complete.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ms.countInserted() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if ms.countInserted() != 1 {
		t.Fatalf("expected 1 entry in store, got %d", ms.countInserted())
	}
}

// TestAuditLogger_ListFromStore verifies that List returns data from the store when configured.
func TestAuditLogger_ListFromStore(t *testing.T) {
	ms := &mockStore{}
	l := newLoggerWithStore(t, ms)

	_, _ = l.Log(audit.EventTokenIssued, "actor-store", "target-1", "issue", "success", nil)

	// Wait for write-through goroutine.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ms.countInserted() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	entries := l.List(audit.AuditFilter{ActorID: "actor-store", Limit: 10})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry from store, got %d", len(entries))
	}
	if entries[0].ActorID != "actor-store" {
		t.Fatalf("unexpected actor_id: %s", entries[0].ActorID)
	}
}

// TestAuditLogger_RetryOnFailure verifies that Insert is retried on transient errors.
func TestAuditLogger_RetryOnFailure(t *testing.T) {
	// First 2 calls fail, 3rd succeeds.
	ms := &mockStore{
		insertErrs: []error{
			errors.New("transient error 1"),
			errors.New("transient error 2"),
			nil, // success on 3rd attempt
		},
	}
	l := newLoggerWithStore(t, ms)

	_, _ = l.Log(audit.EventTokenIssued, "actor-retry", "target-1", "issue", "success", nil)

	// Wait for retry logic (2 retries × 100ms sleep + buffer).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ms.countInserted() >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if ms.countInserted() != 1 {
		t.Fatalf("expected entry to be persisted after retries, got %d entries", ms.countInserted())
	}
}
