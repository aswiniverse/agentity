package store_test

import (
	"testing"
	"time"

	"github.com/agentity/agentity/internal/identity"
	"github.com/agentity/agentity/internal/store"
)

func newAgent(id, name, status string, parentID string) *identity.AgentIdentity {
	return &identity.AgentIdentity{
		ID:        id,
		Name:      name,
		PublicKey: "pubkey-" + id,
		KeyID:     "kid-" + id,
		Status:    identity.AgentStatus(status),
		ParentID:  parentID,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

func TestMemoryStore_CreateAndGet(t *testing.T) {
	s := store.NewMemoryStore()
	agent := newAgent("agent://1", "test-agent", "active", "")

	if err := s.CreateAgent(agent); err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	got, err := s.GetAgent("agent://1")
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if got.Name != "test-agent" {
		t.Fatalf("expected name=test-agent, got %s", got.Name)
	}
}

func TestMemoryStore_GetUnknownAgent(t *testing.T) {
	s := store.NewMemoryStore()
	_, err := s.GetAgent("agent://does-not-exist")
	if err == nil {
		t.Fatal("expected error for unknown agent")
	}
}

func TestMemoryStore_Update(t *testing.T) {
	s := store.NewMemoryStore()
	agent := newAgent("agent://2", "before", "active", "")
	_ = s.CreateAgent(agent)

	agent.Name = "after"
	agent.Status = identity.AgentStatusSuspended
	if err := s.UpdateAgent(agent); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}

	got, _ := s.GetAgent("agent://2")
	if got.Name != "after" {
		t.Fatalf("expected name=after, got %s", got.Name)
	}
	if got.Status != identity.AgentStatusSuspended {
		t.Fatalf("expected status=suspended, got %s", got.Status)
	}
}

func TestMemoryStore_UpdateUnknown(t *testing.T) {
	s := store.NewMemoryStore()
	err := s.UpdateAgent(newAgent("agent://ghost", "x", "active", ""))
	if err == nil {
		t.Fatal("expected error updating non-existent agent")
	}
}

func TestMemoryStore_Delete(t *testing.T) {
	s := store.NewMemoryStore()
	agent := newAgent("agent://del", "to-delete", "active", "")
	_ = s.CreateAgent(agent)

	if err := s.DeleteAgent("agent://del"); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}
	_, err := s.GetAgent("agent://del")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestMemoryStore_DeleteUnknown(t *testing.T) {
	s := store.NewMemoryStore()
	err := s.DeleteAgent("agent://not-there")
	if err == nil {
		t.Fatal("expected error deleting non-existent agent")
	}
}

func TestMemoryStore_ListAgents(t *testing.T) {
	s := store.NewMemoryStore()
	_ = s.CreateAgent(newAgent("agent://a1", "alpha", "active", ""))
	_ = s.CreateAgent(newAgent("agent://a2", "beta", "active", ""))
	_ = s.CreateAgent(newAgent("agent://a3", "gamma", "suspended", ""))

	all, err := s.ListAgents(identity.AgentFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 agents, got %d", len(all))
	}

	active, err := s.ListAgents(identity.AgentFilter{Status: identity.AgentStatusActive, Limit: 10})
	if err != nil {
		t.Fatalf("ListAgents (active filter): %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("expected 2 active agents, got %d", len(active))
	}
}

func TestMemoryStore_GetAgentByKeyID(t *testing.T) {
	s := store.NewMemoryStore()
	agent := newAgent("agent://kl", "key-lookup", "active", "")
	_ = s.CreateAgent(agent)

	got, err := s.GetAgentByKeyID("kid-agent://kl")
	if err != nil {
		t.Fatalf("GetAgentByKeyID: %v", err)
	}
	if got.ID != "agent://kl" {
		t.Fatalf("expected ID=agent://kl, got %s", got.ID)
	}
}

func TestMemoryStore_GetAgentByKeyID_Unknown(t *testing.T) {
	s := store.NewMemoryStore()
	_, err := s.GetAgentByKeyID("kid-does-not-exist")
	if err == nil {
		t.Fatal("expected error for unknown key ID")
	}
}

func TestMemoryStore_GetAgentByKeyID_UpdatedAfterRotation(t *testing.T) {
	s := store.NewMemoryStore()
	agent := newAgent("agent://rot", "rotate-me", "active", "")
	_ = s.CreateAgent(agent)

	// Simulate key rotation.
	agent.KeyID = "kid-new"
	agent.PublicKey = "pubkey-new"
	_ = s.UpdateAgent(agent)

	// Old key ID should no longer resolve.
	_, err := s.GetAgentByKeyID("kid-agent://rot")
	if err == nil {
		t.Fatal("expected error for old key ID after rotation")
	}

	// New key ID should resolve.
	got, err := s.GetAgentByKeyID("kid-new")
	if err != nil {
		t.Fatalf("GetAgentByKeyID with new key: %v", err)
	}
	if got.ID != "agent://rot" {
		t.Fatalf("expected ID=agent://rot, got %s", got.ID)
	}
}

func TestMemoryStore_GetChildAgents(t *testing.T) {
	s := store.NewMemoryStore()
	parent := newAgent("agent://parent", "parent", "active", "")
	child1 := newAgent("agent://c1", "child-1", "active", "agent://parent")
	child2 := newAgent("agent://c2", "child-2", "active", "agent://parent")
	other := newAgent("agent://other", "other", "active", "")

	_ = s.CreateAgent(parent)
	_ = s.CreateAgent(child1)
	_ = s.CreateAgent(child2)
	_ = s.CreateAgent(other)

	children, err := s.GetChildAgents("agent://parent")
	if err != nil {
		t.Fatalf("GetChildAgents: %v", err)
	}
	if len(children) != 2 {
		t.Fatalf("expected 2 children, got %d", len(children))
	}
}

func TestMemoryStore_ListAgents_DefaultLimit(t *testing.T) {
	s := store.NewMemoryStore()
	for i := 0; i < 5; i++ {
		_ = s.CreateAgent(newAgent("agent://"+string(rune('a'+i)), "agent", "active", ""))
	}
	// Limit 0 should be treated as default (50).
	agents, err := s.ListAgents(identity.AgentFilter{Limit: 0})
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 5 {
		t.Fatalf("expected 5 agents with default limit, got %d", len(agents))
	}
}
