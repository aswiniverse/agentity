package policy_test

import (
	"context"
	"testing"

	"github.com/agentity/agentity/internal/policy"
)

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
	e.AddPolicy("allow-read", `"read" in capabilities`, "allow", 0)

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
	e.AddPolicy("allow-all", `true`, "allow", 0)
	e.AddPolicy("deny-deep-chain", `chain_depth > 2`, "deny", 100)

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
	e.AddPolicy("allow-all", `true`, "allow", 0)
	e.AddPolicy("deny-deep", `chain_depth > 5`, "deny", 100)

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
	e.AddPolicy("allow-gpt4", `agent_model == "gpt-4"`, "allow", 0)

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
