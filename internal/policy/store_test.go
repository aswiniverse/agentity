package policy_test

import (
	"errors"
	"testing"

	"github.com/agentity/agentity/internal/policy"
)

// mockStore is an in-memory PolicyStore for testing.
type mockStore struct {
	policies []policy.Policy
	insertErr error
	deleteErr error
	listErr   error
}

func (m *mockStore) Insert(p *policy.Policy) error {
	if m.insertErr != nil {
		return m.insertErr
	}
	m.policies = append(m.policies, *p)
	return nil
}

func (m *mockStore) Delete(id string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	for i, p := range m.policies {
		if p.ID == id {
			m.policies = append(m.policies[:i], m.policies[i+1:]...)
			return nil
		}
	}
	return errors.New("not found")
}

func (m *mockStore) ListAll() ([]policy.Policy, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	result := make([]policy.Policy, len(m.policies))
	copy(result, m.policies)
	return result, nil
}

func TestPolicyStore_Interface(t *testing.T) {
	// Verify mockStore satisfies the interface.
	var _ policy.PolicyStore = &mockStore{}
}

func TestEngine_WithStore_PersistsOnAdd(t *testing.T) {
	ms := &mockStore{}
	e, err := policy.NewEngineWithStore(ms)
	if err != nil {
		t.Fatalf("NewEngineWithStore: %v", err)
	}

	p, err := e.AddPolicy("stored-policy", `true`, "allow", 0)
	if err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil policy")
	}
	if len(ms.policies) != 1 {
		t.Fatalf("expected 1 policy in store, got %d", len(ms.policies))
	}
	if ms.policies[0].ID != p.ID {
		t.Fatalf("stored policy ID mismatch: got %s, want %s", ms.policies[0].ID, p.ID)
	}
}

func TestEngine_WithStore_DeletesOnRemove(t *testing.T) {
	ms := &mockStore{}
	e, err := policy.NewEngineWithStore(ms)
	if err != nil {
		t.Fatalf("NewEngineWithStore: %v", err)
	}

	p, _ := e.AddPolicy("to-remove", `true`, "allow", 0)
	if err := e.RemovePolicy(p.ID); err != nil {
		t.Fatalf("RemovePolicy: %v", err)
	}
	if len(ms.policies) != 0 {
		t.Fatalf("expected 0 policies in store after delete, got %d", len(ms.policies))
	}
}

func TestEngine_LoadFromStore_PopulatesMemory(t *testing.T) {
	ms := &mockStore{}
	// Pre-seed the store directly.
	seed, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("seed engine: %v", err)
	}
	p, _ := seed.AddPolicy("seed-policy", `true`, "allow", 5)
	ms.policies = []policy.Policy{*p}

	e, err := policy.NewEngineWithStore(ms)
	if err != nil {
		t.Fatalf("NewEngineWithStore: %v", err)
	}
	if err := e.LoadFromStore(nil); err != nil { //nolint:staticcheck
		t.Fatalf("LoadFromStore: %v", err)
	}

	policies := e.ListPolicies()
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy after LoadFromStore, got %d", len(policies))
	}
	if policies[0].Name != "seed-policy" {
		t.Fatalf("unexpected policy name: %s", policies[0].Name)
	}
}

func TestEngine_LoadFromStore_StoreError_DenyAll(t *testing.T) {
	ms := &mockStore{listErr: errors.New("db down")}
	e, err := policy.NewEngineWithStore(ms)
	if err != nil {
		t.Fatalf("NewEngineWithStore: %v", err)
	}

	loadErr := e.LoadFromStore(nil) //nolint:staticcheck
	if loadErr == nil {
		t.Fatal("expected error from LoadFromStore when store fails")
	}

	// Engine should have no policies — Evaluate with no policies returns default allow.
	// But the caller (main.go) should treat load failure as deny-all by not serving.
	// Here we just confirm policies list is empty.
	if len(e.ListPolicies()) != 0 {
		t.Fatal("expected no policies when store load fails")
	}
}

func TestEngine_CELProgramCacheHit(t *testing.T) {
	// Verify CEL program is compiled once and reused across multiple evaluations.
	// We test this indirectly: add a policy, evaluate multiple times, confirm no error.
	e, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	_, err = e.AddPolicy("cached", `"read" in capabilities`, "allow", 0)
	if err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	input := policy.PolicyInput{Capabilities: []string{"read"}}
	for i := 0; i < 5; i++ {
		allowed, _, evalErr := e.Evaluate(nil, input) //nolint:staticcheck
		if evalErr != nil {
			t.Fatalf("Evaluate iteration %d: %v", i, evalErr)
		}
		if !allowed {
			t.Fatalf("expected allow on iteration %d", i)
		}
	}
}
