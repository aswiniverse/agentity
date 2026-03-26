package store_test

import (
	"strings"
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

// TestMemoryStore_CreateDuplicate verifies that creating an agent with a duplicate ID returns an error.
func TestMemoryStore_CreateDuplicate(t *testing.T) {
	s := store.NewMemoryStore()
	agent := newAgent("agent://dup", "dup-agent", "active", "")
	if err := s.CreateAgent(agent); err != nil {
		t.Fatalf("first CreateAgent: %v", err)
	}
	err := s.CreateAgent(agent)
	if err == nil {
		t.Fatal("expected error on duplicate CreateAgent")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' in error, got: %v", err)
	}
}

// TestMemoryStore_ListAgents_ParentIDFilter verifies filtering agents by parentID.
func TestMemoryStore_ListAgents_ParentIDFilter(t *testing.T) {
	s := store.NewMemoryStore()
	_ = s.CreateAgent(newAgent("agent://p1", "parent", "active", ""))
	_ = s.CreateAgent(newAgent("agent://c1", "child-1", "active", "agent://p1"))
	_ = s.CreateAgent(newAgent("agent://c2", "child-2", "active", "agent://p1"))
	_ = s.CreateAgent(newAgent("agent://c3", "unrelated", "active", "agent://other"))

	results, err := s.ListAgents(identity.AgentFilter{ParentID: "agent://p1", Limit: 10})
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 agents with parentID=agent://p1, got %d", len(results))
	}
	for _, a := range results {
		if a.ParentID != "agent://p1" {
			t.Errorf("expected parentID=agent://p1, got %s", a.ParentID)
		}
	}
}

// TestMemoryStore_ListAgents_ModelFilter verifies filtering agents by model.
func TestMemoryStore_ListAgents_ModelFilter(t *testing.T) {
	s := store.NewMemoryStore()

	agentGPT := newAgent("agent://gpt", "gpt-agent", "active", "")
	agentGPT.Fingerprint = identity.AgentFingerprint{Model: "gpt-4"}

	agentClaude := newAgent("agent://claude", "claude-agent", "active", "")
	agentClaude.Fingerprint = identity.AgentFingerprint{Model: "claude-3"}

	agentOther := newAgent("agent://other", "other-agent", "active", "")
	agentOther.Fingerprint = identity.AgentFingerprint{Model: "gpt-4"}

	_ = s.CreateAgent(agentGPT)
	_ = s.CreateAgent(agentClaude)
	_ = s.CreateAgent(agentOther)

	results, err := s.ListAgents(identity.AgentFilter{Model: "gpt-4", Limit: 10})
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 agents with model=gpt-4, got %d", len(results))
	}
	for _, a := range results {
		if a.Fingerprint.Model != "gpt-4" {
			t.Errorf("expected model=gpt-4, got %s", a.Fingerprint.Model)
		}
	}
}

// TestMemoryStore_ListAgents_Offset verifies that Offset skips the correct number of entries.
func TestMemoryStore_ListAgents_Offset(t *testing.T) {
	s := store.NewMemoryStore()
	for i := 0; i < 5; i++ {
		_ = s.CreateAgent(newAgent("agent://off-"+string(rune('a'+i)), "agent", "active", ""))
	}

	results, err := s.ListAgents(identity.AgentFilter{Offset: 3, Limit: 10})
	if err != nil {
		t.Fatalf("ListAgents with offset: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 agents after offset=3, got %d", len(results))
	}
}

// TestMemoryStore_GetChildAgents_NoChildren verifies that GetChildAgents returns an empty slice when there are no children.
func TestMemoryStore_GetChildAgents_NoChildren(t *testing.T) {
	s := store.NewMemoryStore()
	_ = s.CreateAgent(newAgent("agent://lonely", "lonely", "active", ""))

	children, err := s.GetChildAgents("agent://lonely")
	if err != nil {
		t.Fatalf("GetChildAgents: %v", err)
	}
	if len(children) != 0 {
		t.Fatalf("expected 0 children, got %d", len(children))
	}
}

// TestMemoryStore_UpdateAgent_KeyRotation verifies that key rotation updates the key index properly.
func TestMemoryStore_UpdateAgent_KeyRotation(t *testing.T) {
	s := store.NewMemoryStore()
	agent := &identity.AgentIdentity{
		ID:        "agent://rot2",
		Name:      "rotate-me",
		PublicKey: "pubkey-old",
		KeyID:     "keyID-old",
		Status:    identity.AgentStatusActive,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := s.CreateAgent(agent); err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	agent.KeyID = "keyID-new"
	agent.PublicKey = "pubkey-new"
	if err := s.UpdateAgent(agent); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}

	// New key ID should resolve.
	got, err := s.GetAgentByKeyID("keyID-new")
	if err != nil {
		t.Fatalf("GetAgentByKeyID(new): %v", err)
	}
	if got.ID != "agent://rot2" {
		t.Errorf("expected ID=agent://rot2, got %s", got.ID)
	}

	// Old key ID should no longer resolve.
	_, err = s.GetAgentByKeyID("keyID-old")
	if err == nil {
		t.Fatal("expected error for old key ID after rotation")
	}
}
