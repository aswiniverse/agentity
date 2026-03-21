package identity_test

import (
	"testing"

	"github.com/agentity/agentity/internal/identity"
	"github.com/agentity/agentity/internal/store"
)

func newService() *identity.Service {
	return identity.NewService(store.NewMemoryStore())
}

func TestRegisterAgent(t *testing.T) {
	svc := newService()

	agent, privKey, err := svc.RegisterAgent(identity.RegisterAgentRequest{
		Name:  "test-agent",
		Model: "claude-3",
		Tools: []string{"read_file"},
	})
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	if agent == nil {
		t.Fatal("expected non-nil agent")
	}
	if agent.ID == "" {
		t.Fatal("expected non-empty agent ID")
	}
	if privKey == "" {
		t.Fatal("expected non-empty private key")
	}
	if agent.Status != identity.AgentStatusActive {
		t.Fatalf("expected status=active, got %s", agent.Status)
	}
	if agent.PublicKey == "" {
		t.Fatal("expected non-empty public key")
	}
	if agent.KeyID == "" {
		t.Fatal("expected non-empty key ID")
	}
}

func TestRegisterAgent_EmptyName(t *testing.T) {
	svc := newService()
	_, _, err := svc.RegisterAgent(identity.RegisterAgentRequest{})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestRegisterAgent_WithParent(t *testing.T) {
	svc := newService()
	parent, _, _ := svc.RegisterAgent(identity.RegisterAgentRequest{Name: "parent"})
	child, _, err := svc.RegisterAgent(identity.RegisterAgentRequest{
		Name:     "child",
		ParentID: parent.ID,
	})
	if err != nil {
		t.Fatalf("RegisterAgent child: %v", err)
	}
	if child.ParentID != parent.ID {
		t.Fatalf("expected ParentID=%s, got %s", parent.ID, child.ParentID)
	}
}

func TestGetAgent(t *testing.T) {
	svc := newService()
	agent, _, _ := svc.RegisterAgent(identity.RegisterAgentRequest{Name: "get-me"})

	got, err := svc.GetAgent(agent.ID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if got.ID != agent.ID {
		t.Fatalf("ID mismatch: %s vs %s", got.ID, agent.ID)
	}
}

func TestGetAgent_Unknown(t *testing.T) {
	svc := newService()
	_, err := svc.GetAgent("agent://nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown agent")
	}
}

func TestListAgents(t *testing.T) {
	svc := newService()
	svc.RegisterAgent(identity.RegisterAgentRequest{Name: "a1"})
	svc.RegisterAgent(identity.RegisterAgentRequest{Name: "a2"})
	svc.RegisterAgent(identity.RegisterAgentRequest{Name: "a3"})

	agents, err := svc.ListAgents(identity.AgentFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 3 {
		t.Fatalf("expected 3 agents, got %d", len(agents))
	}
}

func TestSuspendAgent(t *testing.T) {
	svc := newService()
	agent, _, _ := svc.RegisterAgent(identity.RegisterAgentRequest{Name: "suspendable"})

	if err := svc.SuspendAgent(agent.ID); err != nil {
		t.Fatalf("SuspendAgent: %v", err)
	}

	got, _ := svc.GetAgent(agent.ID)
	if got.Status != identity.AgentStatusSuspended {
		t.Fatalf("expected status=suspended, got %s", got.Status)
	}
}

func TestSuspendAgent_AlreadyRevoked(t *testing.T) {
	svc := newService()
	agent, _, _ := svc.RegisterAgent(identity.RegisterAgentRequest{Name: "revoked-before-suspend"})
	svc.RevokeAgent(agent.ID, false)

	err := svc.SuspendAgent(agent.ID)
	if err == nil {
		t.Fatal("expected error suspending a revoked agent")
	}
}

func TestRevokeAgent(t *testing.T) {
	svc := newService()
	agent, _, _ := svc.RegisterAgent(identity.RegisterAgentRequest{Name: "revocable"})

	if err := svc.RevokeAgent(agent.ID, false); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}

	got, _ := svc.GetAgent(agent.ID)
	if got.Status != identity.AgentStatusRevoked {
		t.Fatalf("expected status=revoked, got %s", got.Status)
	}
}

func TestRevokeAgent_Cascade(t *testing.T) {
	svc := newService()
	parent, _, _ := svc.RegisterAgent(identity.RegisterAgentRequest{Name: "parent"})
	child, _, _ := svc.RegisterAgent(identity.RegisterAgentRequest{Name: "child", ParentID: parent.ID})
	grandchild, _, _ := svc.RegisterAgent(identity.RegisterAgentRequest{Name: "grandchild", ParentID: child.ID})

	if err := svc.RevokeAgent(parent.ID, true); err != nil {
		t.Fatalf("RevokeAgent cascade: %v", err)
	}

	for _, id := range []string{parent.ID, child.ID, grandchild.ID} {
		got, _ := svc.GetAgent(id)
		if got.Status != identity.AgentStatusRevoked {
			t.Fatalf("expected agent %s to be revoked after cascade, got %s", id, got.Status)
		}
	}
}

func TestRotateKey(t *testing.T) {
	svc := newService()
	agent, _, _ := svc.RegisterAgent(identity.RegisterAgentRequest{Name: "rotate-me"})
	originalKeyID := agent.KeyID

	updated, newPrivKey, err := svc.RotateKey(agent.ID)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if newPrivKey == "" {
		t.Fatal("expected non-empty new private key")
	}
	if updated.KeyID == originalKeyID {
		t.Fatal("expected key ID to change after rotation")
	}
	if updated.PublicKey == agent.PublicKey {
		t.Fatal("expected public key to change after rotation")
	}
}

func TestRotateKey_NotActiveAgent(t *testing.T) {
	svc := newService()
	agent, _, _ := svc.RegisterAgent(identity.RegisterAgentRequest{Name: "suspended-rotate"})
	svc.SuspendAgent(agent.ID)

	_, _, err := svc.RotateKey(agent.ID)
	if err == nil {
		t.Fatal("expected error rotating key for suspended agent")
	}
}

func TestGetDelegationTree(t *testing.T) {
	svc := newService()
	parent, _, _ := svc.RegisterAgent(identity.RegisterAgentRequest{Name: "tree-root"})
	svc.RegisterAgent(identity.RegisterAgentRequest{Name: "child-1", ParentID: parent.ID})
	svc.RegisterAgent(identity.RegisterAgentRequest{Name: "child-2", ParentID: parent.ID})

	tree, err := svc.GetDelegationTree(parent.ID)
	if err != nil {
		t.Fatalf("GetDelegationTree: %v", err)
	}
	if tree.Agent.ID != parent.ID {
		t.Fatalf("expected root agent ID=%s, got %s", parent.ID, tree.Agent.ID)
	}
	if len(tree.Children) != 2 {
		t.Fatalf("expected 2 children, got %d", len(tree.Children))
	}
}

func TestGetDelegationTree_Unknown(t *testing.T) {
	svc := newService()
	_, err := svc.GetDelegationTree("agent://nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown root agent")
	}
}
