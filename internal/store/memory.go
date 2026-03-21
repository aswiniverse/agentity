package store

import (
	"fmt"
	"sync"

	"github.com/agentity/agentity/internal/identity"
)

// MemoryStore is an in-memory implementation of identity.Store for dev/testing.
type MemoryStore struct {
	mu     sync.RWMutex
	agents map[string]*identity.AgentIdentity
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		agents: make(map[string]*identity.AgentIdentity),
	}
}

// CreateAgent stores a new agent identity.
func (s *MemoryStore) CreateAgent(agent *identity.AgentIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.agents[agent.ID]; exists {
		return fmt.Errorf("agent %s already exists", agent.ID)
	}
	clone := *agent
	s.agents[agent.ID] = &clone
	return nil
}

// GetAgent retrieves an agent by ID.
func (s *MemoryStore) GetAgent(id string) (*identity.AgentIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agent, exists := s.agents[id]
	if !exists {
		return nil, fmt.Errorf("agent %s not found", id)
	}
	clone := *agent
	return &clone, nil
}

// ListAgents returns agents matching the given filter.
func (s *MemoryStore) ListAgents(filter identity.AgentFilter) ([]*identity.AgentIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*identity.AgentIdentity
	for _, agent := range s.agents {
		if filter.Status != "" && agent.Status != filter.Status {
			continue
		}
		if filter.ParentID != "" && agent.ParentID != filter.ParentID {
			continue
		}
		if filter.Model != "" && agent.Fingerprint.Model != filter.Model {
			continue
		}
		clone := *agent
		result = append(result, &clone)
	}

	// Apply offset.
	if filter.Offset > 0 {
		if filter.Offset >= len(result) {
			return nil, nil
		}
		result = result[filter.Offset:]
	}

	// Apply limit.
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if len(result) > limit {
		result = result[:limit]
	}

	return result, nil
}

// UpdateAgent updates an existing agent.
func (s *MemoryStore) UpdateAgent(agent *identity.AgentIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.agents[agent.ID]; !exists {
		return fmt.Errorf("agent %s not found", agent.ID)
	}
	clone := *agent
	s.agents[agent.ID] = &clone
	return nil
}

// DeleteAgent removes an agent by ID.
func (s *MemoryStore) DeleteAgent(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.agents[id]; !exists {
		return fmt.Errorf("agent %s not found", id)
	}
	delete(s.agents, id)
	return nil
}

// GetChildAgents returns all agents whose ParentID matches the given ID.
func (s *MemoryStore) GetChildAgents(parentID string) ([]*identity.AgentIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var children []*identity.AgentIdentity
	for _, agent := range s.agents {
		if agent.ParentID == parentID {
			clone := *agent
			children = append(children, &clone)
		}
	}
	return children, nil
}
