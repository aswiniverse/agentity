package audit_test

import (
	"errors"
	"fmt"
	"sync"
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

// --- helper store types for new tests ---

// failingListStore inserts succeed but List always returns an error.
type failingListStore struct {
	mu      sync.Mutex
	entries []audit.AuditEntry
}

func (f *failingListStore) Insert(entry *audit.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, *entry)
	return nil
}

func (f *failingListStore) List(_ audit.AuditFilter) ([]audit.AuditEntry, error) {
	return nil, fmt.Errorf("db offline")
}

func (f *failingListStore) Count() (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.entries), nil
}

// alwaysFailStore rejects every operation.
type alwaysFailStore struct{}

func (a *alwaysFailStore) Insert(_ *audit.AuditEntry) error {
	return fmt.Errorf("db down")
}

func (a *alwaysFailStore) List(_ audit.AuditFilter) ([]audit.AuditEntry, error) {
	return nil, fmt.Errorf("db down")
}

func (a *alwaysFailStore) Count() (int, error) {
	return 0, fmt.Errorf("db down")
}

// --- new tests ---

// TestAuditLogger_LogDenied verifies LogDenied sets type, outcome, and reason correctly.
func TestAuditLogger_LogDenied(t *testing.T) {
	l := newLogger(t)
	entry, err := l.LogDenied("actor-x", "target-y", "read", "insufficient permissions", nil)
	if err != nil {
		t.Fatalf("LogDenied: %v", err)
	}
	if entry.Type != audit.EventAccessDenied {
		t.Fatalf("expected type=%s, got %s", audit.EventAccessDenied, entry.Type)
	}
	if entry.Outcome != "denied" {
		t.Fatalf("expected outcome=denied, got %s", entry.Outcome)
	}
	if entry.Reason != "insufficient permissions" {
		t.Fatalf("expected reason set, got %q", entry.Reason)
	}
	if entry.Signature == "" {
		t.Fatal("expected non-empty signature")
	}
}

// TestAuditLogger_PersistFailures_AfterExhaustedRetries verifies that
// PersistFailures increments when all 3 Insert attempts fail.
func TestAuditLogger_PersistFailures_AfterExhaustedRetries(t *testing.T) {
	l := newLoggerWithStore(t, &alwaysFailStore{})
	_, _ = l.Log(audit.EventTokenIssued, "actor-fail", "target-fail", "issue", "success", nil)

	// Wait up to 2s for the goroutine (3 retries × 100 ms sleep).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if l.PersistFailures() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if l.PersistFailures() != 1 {
		t.Fatalf("expected PersistFailures=1, got %d", l.PersistFailures())
	}
}

// TestAuditLogger_ListFilter_ByActorID verifies that ActorID filtering works.
func TestAuditLogger_ListFilter_ByActorID(t *testing.T) {
	l := newLogger(t)
	_, _ = l.Log(audit.EventTokenIssued, "alice", "res-1", "issue", "success", nil)
	_, _ = l.Log(audit.EventTokenIssued, "bob", "res-2", "issue", "success", nil)
	_, _ = l.Log(audit.EventTokenIssued, "alice", "res-3", "issue", "success", nil)

	entries := l.List(audit.AuditFilter{ActorID: "alice", Limit: 10})
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries for alice, got %d", len(entries))
	}
	for _, e := range entries {
		if e.ActorID != "alice" {
			t.Fatalf("unexpected actor_id %q in filtered results", e.ActorID)
		}
	}
}

// TestAuditLogger_ListFilter_ByTargetID verifies that TargetID filtering works.
func TestAuditLogger_ListFilter_ByTargetID(t *testing.T) {
	l := newLogger(t)
	_, _ = l.Log(audit.EventTokenIssued, "actor-1", "target-A", "issue", "success", nil)
	_, _ = l.Log(audit.EventTokenIssued, "actor-2", "target-B", "issue", "success", nil)
	_, _ = l.Log(audit.EventTokenIssued, "actor-3", "target-A", "issue", "success", nil)

	entries := l.List(audit.AuditFilter{TargetID: "target-A", Limit: 10})
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries for target-A, got %d", len(entries))
	}
	for _, e := range entries {
		if e.TargetID != "target-A" {
			t.Fatalf("unexpected target_id %q in filtered results", e.TargetID)
		}
	}
}

// TestAuditLogger_ListFilter_ByType verifies that Type filtering works.
func TestAuditLogger_ListFilter_ByType(t *testing.T) {
	l := newLogger(t)
	_, _ = l.Log(audit.EventTokenIssued, "actor-1", "target-1", "issue", "success", nil)
	_, _ = l.Log(audit.EventTokenVerified, "actor-2", "target-2", "verify", "success", nil)
	_, _ = l.Log(audit.EventTokenIssued, "actor-3", "target-3", "issue", "success", nil)

	entries := l.List(audit.AuditFilter{Type: "token.issued", Limit: 10})
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries with type=token.issued, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Type != audit.EventTokenIssued {
			t.Fatalf("unexpected type %q in filtered results", e.Type)
		}
	}
}

// TestAuditLogger_ListOffset_BeyondLength verifies that an offset past the
// end of results returns nil/empty.
func TestAuditLogger_ListOffset_BeyondLength(t *testing.T) {
	l := newLogger(t)
	for i := 0; i < 3; i++ {
		_, _ = l.Log(audit.EventTokenIssued, "a", "b", "issue", "success", nil)
	}
	entries := l.List(audit.AuditFilter{Offset: 10, Limit: 10})
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries with offset beyond length, got %d", len(entries))
	}
}

// TestAuditLogger_ListLimitClamped verifies that Limit > 200 is clamped to 200.
func TestAuditLogger_ListLimitClamped(t *testing.T) {
	l := newLogger(t)
	for i := 0; i < 5; i++ {
		_, _ = l.Log(audit.EventTokenIssued, "a", "b", "issue", "success", nil)
	}
	entries := l.List(audit.AuditFilter{Limit: 300})
	if len(entries) > 200 {
		t.Fatalf("expected at most 200 entries (clamped), got %d", len(entries))
	}
	// All 5 entries should be returned since 5 < 200.
	if len(entries) != 5 {
		t.Fatalf("expected all 5 entries returned, got %d", len(entries))
	}
}

// TestAuditLogger_StoreFallback_OnListError verifies that when the store's
// List returns an error, the logger falls back to in-memory entries.
func TestAuditLogger_StoreFallback_OnListError(t *testing.T) {
	fs := &failingListStore{}
	l := newLoggerWithStore(t, fs)

	_, _ = l.Log(audit.EventTokenIssued, "actor-fallback", "target-1", "issue", "success", nil)

	// Wait for write-through goroutine (Insert succeeds on failingListStore).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, _ := fs.Count()
		if n >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// List should fall back to in-memory because store.List returns an error.
	entries := l.List(audit.AuditFilter{Limit: 10})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry from in-memory fallback, got %d", len(entries))
	}
}

// TestAuditLogger_AllEventTypes verifies that every defined event type can be logged.
func TestAuditLogger_AllEventTypes(t *testing.T) {
	l := newLogger(t)
	types := []audit.AuditEventType{
		audit.EventAgentRegistered,
		audit.EventTokenIssued,
		audit.EventTokenDelegated,
		audit.EventTokenVerified,
		audit.EventTokenRevoked,
		audit.EventAgentRevoked,
		audit.EventPolicyEvaluated,
		audit.EventAccessDenied,
	}
	for _, evType := range types {
		entry, err := l.Log(evType, "actor", "target", "action", "success", nil)
		if err != nil {
			t.Fatalf("Log(%s): %v", evType, err)
		}
		if entry.Type != evType {
			t.Fatalf("expected type=%s, got %s", evType, entry.Type)
		}
	}
	if l.Count() != len(types) {
		t.Fatalf("expected %d entries, got %d", len(types), l.Count())
	}
}

// Ensure the new store types satisfy the AuditStore interface.
var _ audit.AuditStore = &failingListStore{}
var _ audit.AuditStore = &alwaysFailStore{}
