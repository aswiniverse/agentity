package identity

import "time"

// AgentStatus represents the lifecycle state of an agent.
type AgentStatus string

const (
	AgentStatusActive    AgentStatus = "active"
	AgentStatusSuspended AgentStatus = "suspended"
	AgentStatusRevoked   AgentStatus = "revoked"
)

// AgentFingerprint captures the cryptographic identity of an agent's configuration.
type AgentFingerprint struct {
	SystemPromptHash string   `json:"system_prompt_hash"`
	ToolFingerprint  string   `json:"tool_fingerprint"`
	Tools            []string `json:"tools"`
	Model            string   `json:"model"`
}

// AgentIdentity represents a registered agent in the system.
type AgentIdentity struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Version     string            `json:"version"`
	PublicKey   string            `json:"public_key"`
	KeyID       string            `json:"key_id"`
	Fingerprint AgentFingerprint  `json:"fingerprint"`
	ParentID    string            `json:"parent_id,omitempty"`
	Status      AgentStatus       `json:"status"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// RegisterAgentRequest is the input for registering a new agent.
type RegisterAgentRequest struct {
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	Version      string            `json:"version,omitempty"`
	SystemPrompt string            `json:"system_prompt,omitempty"`
	Tools        []string          `json:"tools,omitempty"`
	Model        string            `json:"model,omitempty"`
	ParentID     string            `json:"parent_id,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// AgentFilter is used to filter agents in list queries.
type AgentFilter struct {
	Status   AgentStatus `json:"status,omitempty"`
	ParentID string      `json:"parent_id,omitempty"`
	Model    string      `json:"model,omitempty"`
	Limit    int         `json:"limit,omitempty"`
	Offset   int         `json:"offset,omitempty"`
}

// DelegationTree represents a tree of parent-child agent relationships.
type DelegationTree struct {
	Agent    *AgentIdentity  `json:"agent"`
	Children []*DelegationTree `json:"children,omitempty"`
}

// Store defines the persistence interface for agent identities.
type Store interface {
	CreateAgent(agent *AgentIdentity) error
	GetAgent(id string) (*AgentIdentity, error)
	ListAgents(filter AgentFilter) ([]*AgentIdentity, error)
	UpdateAgent(agent *AgentIdentity) error
	DeleteAgent(id string) error
	GetChildAgents(parentID string) ([]*AgentIdentity, error)
}
