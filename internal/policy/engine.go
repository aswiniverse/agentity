package policy

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/uuid"
)

// Policy defines a CEL-based access control policy.
type Policy struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Expression string    `json:"expression"`
	Priority   int       `json:"priority"`
	Action     string    `json:"action"` // "allow" or "deny"
	CreatedAt  time.Time `json:"created_at"`
}

// PolicyInput provides context for policy evaluation.
type PolicyInput struct {
	AgentID      string                 `json:"agent_id"`
	AgentModel   string                 `json:"agent_model"`
	ChainDepth   int                    `json:"chain_depth"`
	Capabilities []string               `json:"capabilities"`
	Resource     string                 `json:"resource"`
	Action       string                 `json:"action"`
	ExpiresAt    int64                  `json:"expires_at"`
	Context      map[string]interface{} `json:"context"`
}

// EvaluationResult contains the outcome of a policy evaluation.
type EvaluationResult struct {
	Allowed    bool   `json:"allowed"`
	PolicyName string `json:"policy_name,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// Engine evaluates CEL-based policies.
type Engine struct {
	mu          sync.RWMutex
	policies    []Policy
	compiled    map[string]cel.Program
	env         *cel.Env
	store       PolicyStore
	storeFailed bool // true when LoadFromStore failed; causes Evaluate to deny-all
}

// NewEngine creates a new policy engine with CEL environment and no backing store.
func NewEngine() (*Engine, error) {
	return NewEngineWithStore(nil)
}

// NewEngineWithStore creates a new policy engine with an optional backing store.
func NewEngineWithStore(store PolicyStore) (*Engine, error) {
	env, err := cel.NewEnv(
		cel.Variable("agent_id", cel.StringType),
		cel.Variable("agent_model", cel.StringType),
		cel.Variable("chain_depth", cel.IntType),
		cel.Variable("capabilities", cel.ListType(cel.StringType)),
		cel.Variable("resource", cel.StringType),
		cel.Variable("action", cel.StringType),
		cel.Variable("expires_at", cel.IntType),
		cel.StdLib(),
	)
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}
	return &Engine{
		policies: make([]Policy, 0),
		compiled: make(map[string]cel.Program),
		env:      env,
		store:    store,
	}, nil
}

// LoadFromStore loads all policies from the backing store into memory.
// Returns an error if the store is set and ListAll fails.
func (e *Engine) LoadFromStore(ctx context.Context) error {
	if e.store == nil {
		return nil
	}
	policies, err := e.store.ListAll()
	if err != nil {
		e.mu.Lock()
		e.storeFailed = true
		e.mu.Unlock()
		return fmt.Errorf("load policies from store: %w", err)
	}

	// Compile all policies into local variables first; only swap into the engine
	// if ALL compile successfully to avoid a partial/inconsistent state.
	localPolicies := make([]Policy, 0, len(policies))
	localCompiled := make(map[string]cel.Program, len(policies))

	for _, p := range policies {
		ast, issues := e.env.Compile(p.Expression)
		if issues != nil && issues.Err() != nil {
			e.mu.Lock()
			e.storeFailed = true
			e.mu.Unlock()
			return fmt.Errorf("compile policy %q expression: %w", p.Name, issues.Err())
		}
		prg, err := e.env.Program(ast)
		if err != nil {
			e.mu.Lock()
			e.storeFailed = true
			e.mu.Unlock()
			return fmt.Errorf("build program for policy %q: %w", p.Name, err)
		}
		localCompiled[p.ID] = prg
		localPolicies = append(localPolicies, p)
	}

	// All compiled successfully — swap atomically.
	e.mu.Lock()
	e.policies = localPolicies
	e.compiled = localCompiled
	e.storeFailed = false
	e.mu.Unlock()

	// Policies from store are already ordered by priority DESC (ListAll guarantees this).
	return nil
}

// AddPolicy compiles and adds a policy to the engine.
func (e *Engine) AddPolicy(name, expression, action string, priority int) (*Policy, error) {
	if action != "allow" && action != "deny" {
		return nil, fmt.Errorf("action must be 'allow' or 'deny', got %q", action)
	}

	// Validate the CEL expression compiles.
	ast, issues := e.env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile CEL expression: %w", issues.Err())
	}
	// Ensure it evaluates to bool.
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("CEL expression must evaluate to bool, got %s", ast.OutputType())
	}

	prg, err := e.env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("build CEL program: %w", err)
	}

	p := Policy{
		ID:         uuid.New().String(),
		Name:       name,
		Expression: expression,
		Priority:   priority,
		Action:     action,
		CreatedAt:  time.Now().UTC(),
	}

	// Persist to store if configured.
	if e.store != nil {
		if err := e.store.Insert(&p); err != nil {
			return nil, fmt.Errorf("persist policy: %w", err)
		}
	}

	e.mu.Lock()
	e.compiled[p.ID] = prg
	e.policies = append(e.policies, p)
	// Sort by priority descending (higher priority first).
	sort.Slice(e.policies, func(i, j int) bool {
		return e.policies[i].Priority > e.policies[j].Priority
	})
	e.mu.Unlock()

	return &p, nil
}

// RemovePolicy removes a policy by ID.
func (e *Engine) RemovePolicy(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, p := range e.policies {
		if p.ID == id {
			// Delete from store if configured.
			if e.store != nil {
				if err := e.store.Delete(id); err != nil {
					return fmt.Errorf("delete policy from store: %w", err)
				}
			}
			delete(e.compiled, id)
			e.policies = append(e.policies[:i], e.policies[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("policy %s not found", id)
}

// ListPolicies returns all policies.
func (e *Engine) ListPolicies() []Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]Policy, len(e.policies))
	copy(result, e.policies)
	return result
}

// GetPolicy returns a single policy by ID.
func (e *Engine) GetPolicy(id string) (*Policy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, p := range e.policies {
		if p.ID == id {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("policy %s not found", id)
}

// Evaluate runs all policies against the input. Deny policies take precedence.
// Returns whether access is allowed, which policy decided, and a reason.
func (e *Engine) Evaluate(_ context.Context, input PolicyInput) (bool, string, error) {
	// FIX 13: nil-guard capabilities to avoid CEL runtime errors.
	if input.Capabilities == nil {
		input.Capabilities = []string{}
	}

	// FIX 14: read both storeFailed and policies under a single RLock to eliminate TOCTOU.
	e.mu.RLock()
	storeFailed := e.storeFailed
	policies := make([]Policy, len(e.policies))
	copy(policies, e.policies)
	e.mu.RUnlock()

	if storeFailed {
		return false, "policy-store-load-failed", nil
	}

	if len(policies) == 0 {
		// Default allow when no policies are configured (no store, or store is empty).
		return true, "", nil
	}

	activation := map[string]interface{}{
		"agent_id":     input.AgentID,
		"agent_model":  input.AgentModel,
		"chain_depth":  int64(input.ChainDepth),
		"capabilities": input.Capabilities,
		"resource":     input.Resource,
		"action":       input.Action,
		"expires_at":   input.ExpiresAt,
	}

	// Evaluate deny policies first (they take precedence), then allow.
	for _, p := range policies {
		if p.Action != "deny" {
			continue
		}
		matched, err := e.evalPolicy(p, activation)
		if err != nil {
			return false, p.Name, fmt.Errorf("evaluate deny policy %q: %w", p.Name, err)
		}
		if matched {
			return false, p.Name, nil
		}
	}

	// Check allow policies.
	hasAllowPolicy := false
	for _, p := range policies {
		if p.Action != "allow" {
			continue
		}
		hasAllowPolicy = true
		matched, err := e.evalPolicy(p, activation)
		if err != nil {
			return false, p.Name, fmt.Errorf("evaluate allow policy %q: %w", p.Name, err)
		}
		if matched {
			return true, p.Name, nil
		}
	}

	// If there are allow policies but none matched, deny.
	if hasAllowPolicy {
		return false, "", nil
	}

	// No allow policies exist, default allow.
	return true, "", nil
}

func (e *Engine) evalPolicy(p Policy, activation map[string]interface{}) (bool, error) {
	e.mu.RLock()
	prg, cached := e.compiled[p.ID]
	e.mu.RUnlock()

	if !cached {
		// Defensive fallback: compile on-the-fly and cache.
		ast, issues := e.env.Compile(p.Expression)
		if issues != nil && issues.Err() != nil {
			return false, issues.Err()
		}
		var err error
		prg, err = e.env.Program(ast)
		if err != nil {
			return false, fmt.Errorf("create program: %w", err)
		}
		e.mu.Lock()
		e.compiled[p.ID] = prg
		e.mu.Unlock()
	}

	out, _, err := prg.Eval(activation)
	if err != nil {
		return false, fmt.Errorf("eval: %w", err)
	}
	result, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expected bool result, got %T", out.Value())
	}
	return result, nil
}
