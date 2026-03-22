package audit_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/agentity/agentity/internal/audit"
)

// mockStore is an in-memory AuditStore implementation for testing.
type mockStore struct {
	mu      sync.Mutex
	entries []audit.AuditEntry
	// insertErr, if non-nil, is returned by Insert (decremented each call).
	insertErrs []error
}

func (m *mockStore) Insert(entry *audit.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.insertErrs) > 0 {
		err := m.insertErrs[0]
		m.insertErrs = m.insertErrs[1:]
		if err != nil {
			return err
		}
	}
	m.entries = append(m.entries, *entry)
	return nil
}

func (m *mockStore) List(filter audit.AuditFilter) ([]audit.AuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []audit.AuditEntry
	for _, e := range m.entries {
		if filter.ActorID != "" && e.ActorID != filter.ActorID {
			continue
		}
		if filter.Type != "" && string(e.Type) != filter.Type {
			continue
		}
		out = append(out, e)
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *mockStore) Count() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries), nil
}

func (m *mockStore) countInserted() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// TestAuditStore_Interface ensures mockStore satisfies the interface.
func TestAuditStore_Interface(t *testing.T) {
	var _ audit.AuditStore = &mockStore{}
}

// TestMockStore_InsertAndList tests basic Insert+List round-trip.
func TestMockStore_InsertAndList(t *testing.T) {
	ms := &mockStore{}
	entry := &audit.AuditEntry{
		ID:      "test-id",
		Type:    audit.EventTokenIssued,
		ActorID: "actor-1",
		Action:  "issue",
		Outcome: "success",
	}
	if err := ms.Insert(entry); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	entries, err := ms.List(audit.AuditFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].ID != "test-id" {
		t.Fatalf("expected id=test-id, got %s", entries[0].ID)
	}
}

// TestMockStore_Count tests Count after inserts.
func TestMockStore_Count(t *testing.T) {
	ms := &mockStore{}
	for i := 0; i < 3; i++ {
		ms.Insert(&audit.AuditEntry{ID: "id", Type: audit.EventTokenIssued, ActorID: "a", Action: "x", Outcome: "ok"})
	}
	n, err := ms.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3, got %d", n)
	}
}

// TestMockStore_InsertError tests that Insert returns errors when configured.
func TestMockStore_InsertError(t *testing.T) {
	ms := &mockStore{
		insertErrs: []error{errors.New("db down"), nil},
	}
	entry := &audit.AuditEntry{ID: "e1", Type: audit.EventTokenIssued, ActorID: "a", Action: "x", Outcome: "ok"}
	if err := ms.Insert(entry); err == nil {
		t.Fatal("expected error on first Insert")
	}
	if err := ms.Insert(entry); err != nil {
		t.Fatalf("expected nil on second Insert, got: %v", err)
	}
}
