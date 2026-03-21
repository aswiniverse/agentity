package identity_test

import (
	"fmt"
	"testing"

	"github.com/agentity/agentity/internal/identity"
	"github.com/agentity/agentity/internal/store"
)

// buildChain registers n agents in a parent→child chain and returns their IDs
// in order (root first).
func buildChain(t *testing.T, svc *identity.Service, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	parentID := ""
	for i := 0; i < n; i++ {
		req := identity.RegisterAgentRequest{Name: fmt.Sprintf("chain-%d", i)}
		if parentID != "" {
			req.ParentID = parentID
		}
		agent, _, err := svc.RegisterAgent(req)
		if err != nil {
			t.Fatalf("RegisterAgent chain[%d]: %v", i, err)
		}
		ids = append(ids, agent.ID)
		parentID = agent.ID
	}
	return ids
}

func TestRevokeAgent_Cascade_ShallowTree(t *testing.T) {
	svc := identity.NewService(store.NewMemoryStore())
	// 5-level deep chain: root → c1 → c2 → c3 → c4
	ids := buildChain(t, svc, 5)

	// Revoke root with cascade.
	if err := svc.RevokeAgent(ids[0], true); err != nil {
		t.Fatalf("RevokeAgent cascade: %v", err)
	}

	// All agents in the chain should now be revoked.
	for _, id := range ids {
		agent, err := svc.GetAgent(id)
		if err != nil {
			t.Fatalf("GetAgent %s: %v", id, err)
		}
		if agent.Status != identity.AgentStatusRevoked {
			t.Fatalf("expected agent %s to be revoked, got %s", id, agent.Status)
		}
	}
}

func TestRevokeAgent_Cascade_WideBreadthFirstTree(t *testing.T) {
	svc := identity.NewService(store.NewMemoryStore())

	// Register a root with 5 children, each with 3 grandchildren = 1 + 5 + 15 = 21 agents.
	root, _, _ := svc.RegisterAgent(identity.RegisterAgentRequest{Name: "wide-root"})
	var allIDs []string
	allIDs = append(allIDs, root.ID)

	for i := 0; i < 5; i++ {
		child, _, _ := svc.RegisterAgent(identity.RegisterAgentRequest{
			Name:     fmt.Sprintf("child-%d", i),
			ParentID: root.ID,
		})
		allIDs = append(allIDs, child.ID)

		for j := 0; j < 3; j++ {
			gc, _, _ := svc.RegisterAgent(identity.RegisterAgentRequest{
				Name:     fmt.Sprintf("gc-%d-%d", i, j),
				ParentID: child.ID,
			})
			allIDs = append(allIDs, gc.ID)
		}
	}

	if err := svc.RevokeAgent(root.ID, true); err != nil {
		t.Fatalf("RevokeAgent wide cascade: %v", err)
	}

	for _, id := range allIDs {
		agent, _ := svc.GetAgent(id)
		if agent.Status != identity.AgentStatusRevoked {
			t.Fatalf("expected all 21 agents revoked, %s has status %s", id, agent.Status)
		}
	}
}

func TestRevokeAgent_NoCascade_ChildrenUnaffected(t *testing.T) {
	svc := identity.NewService(store.NewMemoryStore())
	ids := buildChain(t, svc, 3) // root → child → grandchild

	// Revoke root WITHOUT cascade.
	if err := svc.RevokeAgent(ids[0], false); err != nil {
		t.Fatalf("RevokeAgent no cascade: %v", err)
	}

	// Root is revoked.
	root, _ := svc.GetAgent(ids[0])
	if root.Status != identity.AgentStatusRevoked {
		t.Fatalf("expected root revoked, got %s", root.Status)
	}

	// Child and grandchild should still be active.
	for _, id := range ids[1:] {
		agent, _ := svc.GetAgent(id)
		if agent.Status != identity.AgentStatusActive {
			t.Fatalf("expected child %s to remain active without cascade, got %s", id, agent.Status)
		}
	}
}

func TestRevokeAgent_Cascade_BFSIterative_DoesNotStackOverflow(t *testing.T) {
	// Build a chain of 50 agents — verifies the iterative BFS doesn't stack
	// overflow the way a recursive approach would on deep trees.
	svc := identity.NewService(store.NewMemoryStore())
	ids := buildChain(t, svc, 50)

	if err := svc.RevokeAgent(ids[0], true); err != nil {
		t.Fatalf("RevokeAgent 50-deep cascade: %v", err)
	}

	// Spot-check a few nodes at various depths.
	for _, idx := range []int{0, 10, 25, 49} {
		agent, _ := svc.GetAgent(ids[idx])
		if agent.Status != identity.AgentStatusRevoked {
			t.Fatalf("expected agent[%d] (%s) to be revoked", idx, ids[idx])
		}
	}
}

func TestRevokeAgent_NonCascade_SingleAgent(t *testing.T) {
	svc := identity.NewService(store.NewMemoryStore())
	agent, _, _ := svc.RegisterAgent(identity.RegisterAgentRequest{Name: "solo"})

	if err := svc.RevokeAgent(agent.ID, false); err != nil {
		t.Fatalf("RevokeAgent solo: %v", err)
	}

	got, _ := svc.GetAgent(agent.ID)
	if got.Status != identity.AgentStatusRevoked {
		t.Fatalf("expected revoked, got %s", got.Status)
	}
}
