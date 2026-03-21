package store

import (
	"fmt"
	"sort"
	"sync"

	"github.com/agentity/agentity/internal/identity"
)

// MemoryStore is an in-memory implementation of identity.Store for dev/testing.
// M5 fix: maintains a secondary keyID→agentID index for O(1) key resolution,
// replacing the O(N) table scan that previously had a hard cap of 1000 agents.
type MemoryStore struct {
	mu       sync.RWMutex
	agents   map[string]*identity.AgentIdentity // id → agent
	keyIndex map[string]string                  // keyID → agent id
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		agents:   make(map[string]*identity.AgentIdentity),
		keyIndex: make(map[string]string),
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
	s.keyIndex[agent.KeyID] = agent.ID
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

// GetAgentByKeyID retrieves an agent by its key ID using the secondary index.
// M5 fix: O(1) lookup instead of O(N) scan.
func (s *MemoryStore) GetAgentByKeyID(keyID string) (*identity.AgentIdentity, error) {
	s.mu.RLock()
	agentID, ok := s.keyIndex[keyID]
	if !ok {
		s.mu.RUnlock()
		return nil, fmt.Errorf("no agent found for key_id %s", keyID)
	}
	agent, exists := s.agents[agentID]
	s.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("agent %s not found", agentID)
	}
	clone := *agent
	return &clone, nil
}

// ListAgents returns agents matching the given filter with deterministic ordering.
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

	// Deterministic ordering (by creation time desc, then ID) so pagination is stable.
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID > result[j].ID
		}
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})

	if filter.Offset > 0 {
		if filter.Offset >= len(result) {
			return nil, nil
		}
		result = result[filter.Offset:]
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if len(result) > limit {
		result = result[:limit]
	}

	return result, nil
}

// UpdateAgent updates an existing agent and refreshes the key index.
func (s *MemoryStore) UpdateAgent(agent *identity.AgentIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, exists := s.agents[agent.ID]
	if !exists {
		return fmt.Errorf("agent %s not found", agent.ID)
	}
	// Remove old key index entry if key rotated.
	if existing.KeyID != agent.KeyID {
		delete(s.keyIndex, existing.KeyID)
		s.keyIndex[agent.KeyID] = agent.ID
	}
	clone := *agent
	s.agents[agent.ID] = &clone
	return nil
}

// DeleteAgent removes an agent by ID and cleans up the key index.
func (s *MemoryStore) DeleteAgent(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, exists := s.agents[id]
	if !exists {
		return fmt.Errorf("agent %s not found", id)
	}
	delete(s.keyIndex, existing.KeyID)
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
