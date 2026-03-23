package policy_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/agentity/agentity/internal/policy"
)

// memPolicyStore is an in-memory PolicyStore used in tests.
type memPolicyStore struct {
	mu       sync.Mutex
	policies []policy.Policy
}

func (m *memPolicyStore) Insert(p *policy.Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies = append(m.policies, *p)
	return nil
}

func (m *memPolicyStore) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, p := range m.policies {
		if p.ID == id {
			m.policies = append(m.policies[:i], m.policies[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("not found")
}

func (m *memPolicyStore) ListAll() ([]policy.Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]policy.Policy{}, m.policies...), nil
}

// failingPolicyStore is a PolicyStore that always returns errors.
type failingPolicyStore struct{}

func (f *failingPolicyStore) Insert(p *policy.Policy) error { return fmt.Errorf("db down") }
func (f *failingPolicyStore) Delete(id string) error        { return fmt.Errorf("db down") }
func (f *failingPolicyStore) ListAll() ([]policy.Policy, error) {
	return nil, fmt.Errorf("db down")
}

func newEngine(t *testing.T) *policy.Engine {
	t.Helper()
	e, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func TestNewEngine(t *testing.T) {
	e := newEngine(t)
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestAddPolicy_Valid(t *testing.T) {
	e := newEngine(t)
	p, err := e.AddPolicy("test-policy", `"read" in capabilities`, "allow", 10)
	if err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if p.ID == "" {
		t.Fatal("expected non-empty policy ID")
	}
	if p.Name != "test-policy" {
		t.Fatalf("expected name=test-policy, got %s", p.Name)
	}
}

func TestAddPolicy_InvalidAction(t *testing.T) {
	e := newEngine(t)
	_, err := e.AddPolicy("bad", `true`, "maybe", 0)
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestAddPolicy_InvalidCEL(t *testing.T) {
	e := newEngine(t)
	_, err := e.AddPolicy("bad-cel", `this is not valid CEL !!!`, "allow", 0)
	if err == nil {
		t.Fatal("expected error for invalid CEL expression")
	}
}

func TestAddPolicy_NonBoolExpression(t *testing.T) {
	e := newEngine(t)
	// Expression returns string, not bool.
	_, err := e.AddPolicy("non-bool", `"hello"`, "allow", 0)
	if err == nil {
		t.Fatal("expected error for non-bool CEL expression")
	}
}

func TestListPolicies(t *testing.T) {
	e := newEngine(t)
	_, _ = e.AddPolicy("p1", `true`, "allow", 5)
	_, _ = e.AddPolicy("p2", `false`, "deny", 10)

	policies := e.ListPolicies()
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}
	// Should be sorted by priority descending: p2 (10) first.
	if policies[0].Name != "p2" {
		t.Fatalf("expected p2 first (higher priority), got %s", policies[0].Name)
	}
}

func TestRemovePolicy(t *testing.T) {
	e := newEngine(t)
	p, _ := e.AddPolicy("removable", `true`, "allow", 0)
	if err := e.RemovePolicy(p.ID); err != nil {
		t.Fatalf("RemovePolicy: %v", err)
	}
	if len(e.ListPolicies()) != 0 {
		t.Fatal("expected empty policy list after removal")
	}
}

func TestRemovePolicy_Unknown(t *testing.T) {
	e := newEngine(t)
	err := e.RemovePolicy("nonexistent-id")
	if err == nil {
		t.Fatal("expected error removing unknown policy")
	}
}

func TestEvaluate_NoPolicies_DefaultAllow(t *testing.T) {
	e := newEngine(t)
	allowed, _, err := e.Evaluate(context.Background(), policy.PolicyInput{
		AgentID:      "agent://x",
		Capabilities: []string{"read"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !allowed {
		t.Fatal("expected default allow when no policies configured")
	}
}

func TestEvaluate_AllowPolicy_Matches(t *testing.T) {
	e := newEngine(t)
	_, _ = e.AddPolicy("allow-read", `"read" in capabilities`, "allow", 0)

	allowed, _, err := e.Evaluate(context.Background(), policy.PolicyInput{
		Capabilities: []string{"read"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !allowed {
		t.Fatal("expected allow for agent with 'read' capability")
	}
}

func TestEvaluate_AllowPolicy_NoMatch(t *testing.T) {
	e := newEngine(t)
	_, _ = e.AddPolicy("allow-read", `"read" in capabilities`, "allow", 0)

	// Agent only has "write" — allow policy doesn't match → deny.
	allowed, _, err := e.Evaluate(context.Background(), policy.PolicyInput{
		Capabilities: []string{"write"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if allowed {
		t.Fatal("expected deny when allow policy doesn't match")
	}
}

func TestEvaluate_DenyPolicy_TakesPrecedence(t *testing.T) {
	e := newEngine(t)
	_, _ = e.AddPolicy("allow-all", `true`, "allow", 0)
	_, _ = e.AddPolicy("deny-deep-chain", `chain_depth > 2`, "deny", 100)

	// Chain depth = 3 → deny policy matches → should be denied.
	allowed, name, err := e.Evaluate(context.Background(), policy.PolicyInput{
		Capabilities: []string{"read"},
		ChainDepth:   3,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if allowed {
		t.Fatal("expected deny policy to take precedence")
	}
	if name != "deny-deep-chain" {
		t.Fatalf("expected denying policy=deny-deep-chain, got %s", name)
	}
}

func TestEvaluate_DenyDoesNotFire_AllowWins(t *testing.T) {
	e := newEngine(t)
	_, _ = e.AddPolicy("allow-all", `true`, "allow", 0)
	_, _ = e.AddPolicy("deny-deep", `chain_depth > 5`, "deny", 100)

	// Chain depth = 1 → deny policy doesn't match → allow wins.
	allowed, _, err := e.Evaluate(context.Background(), policy.PolicyInput{
		Capabilities: []string{"read"},
		ChainDepth:   1,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !allowed {
		t.Fatal("expected allow when deny policy doesn't match")
	}
}

func TestEvaluate_AgentModelFilter(t *testing.T) {
	e := newEngine(t)
	_, _ = e.AddPolicy("allow-gpt4", `agent_model == "gpt-4"`, "allow", 0)

	allowed, _, _ := e.Evaluate(context.Background(), policy.PolicyInput{
		AgentModel:   "gpt-4",
		Capabilities: []string{"read"},
	})
	if !allowed {
		t.Fatal("expected allow for gpt-4 model")
	}

	denied, _, _ := e.Evaluate(context.Background(), policy.PolicyInput{
		AgentModel:   "gpt-3",
		Capabilities: []string{"read"},
	})
	if denied {
		t.Fatal("expected deny for non-gpt-4 model")
	}
}

// TestGetPolicy_Found verifies GetPolicy returns a matching policy after AddPolicy.
func TestGetPolicy_Found(t *testing.T) {
	e := newEngine(t)
	added, err := e.AddPolicy("find-me", `true`, "allow", 5)
	if err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	got, err := e.GetPolicy(added.ID)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.ID != added.ID {
		t.Errorf("ID mismatch: got %s, want %s", got.ID, added.ID)
	}
	if got.Name != "find-me" {
		t.Errorf("Name mismatch: got %s, want find-me", got.Name)
	}
	if got.Action != "allow" {
		t.Errorf("Action mismatch: got %s, want allow", got.Action)
	}
	if got.Priority != 5 {
		t.Errorf("Priority mismatch: got %d, want 5", got.Priority)
	}
}

// TestGetPolicy_NotFound verifies GetPolicy returns an error for an unknown ID.
func TestGetPolicy_NotFound(t *testing.T) {
	e := newEngine(t)
	_, err := e.GetPolicy("00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Fatal("expected error for unknown policy ID")
	}
}

// TestNewEngineWithStore verifies NewEngineWithStore returns a non-nil engine.
func TestNewEngineWithStore(t *testing.T) {
	store := &memPolicyStore{}
	e, err := policy.NewEngineWithStore(store)
	if err != nil {
		t.Fatalf("NewEngineWithStore: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

// TestLoadFromStore_Success verifies that policies inserted directly into the store
// are loaded into the engine and evaluated correctly after LoadFromStore.
func TestLoadFromStore_Success(t *testing.T) {
	store := &memPolicyStore{}
	e, err := policy.NewEngineWithStore(store)
	if err != nil {
		t.Fatalf("NewEngineWithStore: %v", err)
	}

	// Insert a policy directly into the store (bypassing the engine).
	p := &policy.Policy{
		ID:         "aaaaaaaa-0000-0000-0000-000000000001",
		Name:       "store-allow",
		Expression: `"exec" in capabilities`,
		Priority:   1,
		Action:     "allow",
	}
	if err := store.Insert(p); err != nil {
		t.Fatalf("store.Insert: %v", err)
	}

	if err := e.LoadFromStore(context.Background()); err != nil {
		t.Fatalf("LoadFromStore: %v", err)
	}

	allowed, name, err := e.Evaluate(context.Background(), policy.PolicyInput{
		Capabilities: []string{"exec"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !allowed {
		t.Fatal("expected allow for agent with 'exec' capability")
	}
	if name != "store-allow" {
		t.Errorf("expected policy name=store-allow, got %s", name)
	}
}

// TestLoadFromStore_NoStore verifies that LoadFromStore is a no-op when no store is set.
func TestLoadFromStore_NoStore(t *testing.T) {
	e := newEngine(t) // NewEngine() sets store=nil
	if err := e.LoadFromStore(context.Background()); err != nil {
		t.Fatalf("expected nil error with no store, got: %v", err)
	}
}

// TestStoreFailed_DenyAll verifies that after a store load failure, Evaluate deny-alls
// and returns the sentinel policy name "policy-store-load-failed".
func TestStoreFailed_DenyAll(t *testing.T) {
	e, err := policy.NewEngineWithStore(&failingPolicyStore{})
	if err != nil {
		t.Fatalf("NewEngineWithStore: %v", err)
	}

	// LoadFromStore will fail because the store always errors.
	loadErr := e.LoadFromStore(context.Background())
	if loadErr == nil {
		t.Fatal("expected LoadFromStore to return an error")
	}

	allowed, name, err := e.Evaluate(context.Background(), policy.PolicyInput{
		Capabilities: []string{"read"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if allowed {
		t.Fatal("expected deny-all after store load failure")
	}
	if name != "policy-store-load-failed" {
		t.Errorf("expected policy name=policy-store-load-failed, got %s", name)
	}
}

// TestAddPolicy_PersistsToStore verifies AddPolicy writes through to the backing store.
func TestAddPolicy_PersistsToStore(t *testing.T) {
	store := &memPolicyStore{}
	e, err := policy.NewEngineWithStore(store)
	if err != nil {
		t.Fatalf("NewEngineWithStore: %v", err)
	}

	if _, err := e.AddPolicy("persisted", `true`, "allow", 0); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	all, err := store.ListAll()
	if err != nil {
		t.Fatalf("store.ListAll: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 policy in store, got %d", len(all))
	}
	if all[0].Name != "persisted" {
		t.Errorf("expected policy name=persisted, got %s", all[0].Name)
	}
}

// TestRemovePolicy_DeletesFromStore verifies RemovePolicy removes the policy from the store.
func TestRemovePolicy_DeletesFromStore(t *testing.T) {
	store := &memPolicyStore{}
	e, err := policy.NewEngineWithStore(store)
	if err != nil {
		t.Fatalf("NewEngineWithStore: %v", err)
	}

	p, err := e.AddPolicy("to-delete", `true`, "deny", 0)
	if err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	if err := e.RemovePolicy(p.ID); err != nil {
		t.Fatalf("RemovePolicy: %v", err)
	}

	all, err := store.ListAll()
	if err != nil {
		t.Fatalf("store.ListAll: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("expected 0 policies in store after removal, got %d", len(all))
	}
}

// TestEvaluate_NilCapabilities verifies Evaluate handles nil Capabilities without error.
func TestEvaluate_NilCapabilities(t *testing.T) {
	e := newEngine(t)
	if _, err := e.AddPolicy("allow-all", `true`, "allow", 0); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	allowed, _, err := e.Evaluate(context.Background(), policy.PolicyInput{
		Capabilities: nil,
	})
	if err != nil {
		t.Fatalf("Evaluate with nil capabilities: %v", err)
	}
	if !allowed {
		t.Fatal("expected allowed=true for unconditional allow policy with nil capabilities")
	}
}

// TestEvaluate_OnlyDenyPolicies_DefaultAllow verifies that when only deny policies exist
// and none match, the engine defaults to allow (no allow policies → default allow).
func TestEvaluate_OnlyDenyPolicies_DefaultAllow(t *testing.T) {
	e := newEngine(t)
	// Deny policy that only triggers for chain_depth > 10.
	if _, err := e.AddPolicy("deny-deep", `chain_depth > 10`, "deny", 5); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	// Input with chain_depth=1 does not match the deny policy.
	allowed, _, err := e.Evaluate(context.Background(), policy.PolicyInput{
		Capabilities: []string{"read"},
		ChainDepth:   1,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !allowed {
		t.Fatal("expected default allow when only deny policies exist and none match")
	}
}

// TestEvaluate_StoreFailed_DenyAll is an explicit alias verifying the storeFailed
// path produces allowed=false and the sentinel name, consistent with TestStoreFailed_DenyAll.
func TestEvaluate_StoreFailed_DenyAll(t *testing.T) {
	e, err := policy.NewEngineWithStore(&failingPolicyStore{})
	if err != nil {
		t.Fatalf("NewEngineWithStore: %v", err)
	}

	// Trigger storeFailed by calling LoadFromStore (it will fail).
	_ = e.LoadFromStore(context.Background())

	allowed, name, err := e.Evaluate(context.Background(), policy.PolicyInput{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if allowed {
		t.Fatal("expected allowed=false when storeFailed is set")
	}
	if name != "policy-store-load-failed" {
		t.Errorf("expected name=policy-store-load-failed, got %q", name)
	}
}
