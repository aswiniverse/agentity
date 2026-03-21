package identity

import (
	"fmt"
	"time"

	agcrypto "github.com/agentity/agentity/pkg/crypto"
	"github.com/google/uuid"
)

// Service handles agent identity lifecycle operations.
type Service struct {
	store Store
}

// NewService creates a new identity service.
func NewService(store Store) *Service {
	return &Service{store: store}
}

// RegisterAgent creates a new agent identity, generates a key pair, and returns the identity
// along with the base64url-encoded private key (returned only once).
func (s *Service) RegisterAgent(req RegisterAgentRequest) (*AgentIdentity, string, error) {
	if req.Name == "" {
		return nil, "", fmt.Errorf("agent name is required")
	}

	kp, err := agcrypto.GenerateKeyPair()
	if err != nil {
		return nil, "", fmt.Errorf("generate key pair: %w", err)
	}

	promptHash := ""
	if req.SystemPrompt != "" {
		promptHash = agcrypto.ComputeSystemPromptHash(req.SystemPrompt)
	}
	toolFP := agcrypto.ComputeToolFingerprint(req.Tools)

	now := time.Now().UTC()
	agent := &AgentIdentity{
		ID:        "agent://" + uuid.New().String(),
		Name:      req.Name,
		Description: req.Description,
		Version:   req.Version,
		PublicKey: agcrypto.EncodePublicKeyBase64(kp.PublicKey),
		KeyID:     kp.KeyID,
		Fingerprint: AgentFingerprint{
			SystemPromptHash: promptHash,
			ToolFingerprint:  toolFP,
			Tools:            req.Tools,
			Model:            req.Model,
		},
		ParentID:  req.ParentID,
		Status:    AgentStatusActive,
		Metadata:  req.Metadata,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.store.CreateAgent(agent); err != nil {
		return nil, "", fmt.Errorf("create agent: %w", err)
	}

	privKeyB64 := agcrypto.EncodePrivateKeyBase64(kp.PrivateKey)
	return agent, privKeyB64, nil
}

// GetAgent retrieves an agent by ID.
func (s *Service) GetAgent(id string) (*AgentIdentity, error) {
	agent, err := s.store.GetAgent(id)
	if err != nil {
		return nil, fmt.Errorf("get agent: %w", err)
	}
	return agent, nil
}

// ListAgents returns agents matching the given filter.
func (s *Service) ListAgents(filter AgentFilter) ([]*AgentIdentity, error) {
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > 200 {
		filter.Limit = 200
	}
	agents, err := s.store.ListAgents(filter)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	return agents, nil
}

// SuspendAgent marks an agent as suspended.
func (s *Service) SuspendAgent(id string) error {
	agent, err := s.store.GetAgent(id)
	if err != nil {
		return fmt.Errorf("get agent: %w", err)
	}
	if agent.Status == AgentStatusRevoked {
		return fmt.Errorf("cannot suspend a revoked agent")
	}
	agent.Status = AgentStatusSuspended
	agent.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateAgent(agent); err != nil {
		return fmt.Errorf("update agent: %w", err)
	}
	return nil
}

// RevokeAgent marks an agent as revoked. If cascade is true, all child agents are also revoked.
func (s *Service) RevokeAgent(id string, cascade bool) error {
	agent, err := s.store.GetAgent(id)
	if err != nil {
		return fmt.Errorf("get agent: %w", err)
	}
	agent.Status = AgentStatusRevoked
	agent.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateAgent(agent); err != nil {
		return fmt.Errorf("update agent: %w", err)
	}

	if cascade {
		if err := s.revokeChildren(id); err != nil {
			return fmt.Errorf("revoke children: %w", err)
		}
	}
	return nil
}

func (s *Service) revokeChildren(parentID string) error {
	children, err := s.store.GetChildAgents(parentID)
	if err != nil {
		return err
	}
	for _, child := range children {
		child.Status = AgentStatusRevoked
		child.UpdatedAt = time.Now().UTC()
		if err := s.store.UpdateAgent(child); err != nil {
			return err
		}
		if err := s.revokeChildren(child.ID); err != nil {
			return err
		}
	}
	return nil
}

// RotateKey generates a new key pair for an agent and returns the updated identity
// and the new base64url-encoded private key.
func (s *Service) RotateKey(id string) (*AgentIdentity, string, error) {
	agent, err := s.store.GetAgent(id)
	if err != nil {
		return nil, "", fmt.Errorf("get agent: %w", err)
	}
	if agent.Status != AgentStatusActive {
		return nil, "", fmt.Errorf("can only rotate keys for active agents")
	}

	kp, err := agcrypto.GenerateKeyPair()
	if err != nil {
		return nil, "", fmt.Errorf("generate key pair: %w", err)
	}

	agent.PublicKey = agcrypto.EncodePublicKeyBase64(kp.PublicKey)
	agent.KeyID = kp.KeyID
	agent.UpdatedAt = time.Now().UTC()

	if err := s.store.UpdateAgent(agent); err != nil {
		return nil, "", fmt.Errorf("update agent: %w", err)
	}

	privKeyB64 := agcrypto.EncodePrivateKeyBase64(kp.PrivateKey)
	return agent, privKeyB64, nil
}

// GetDelegationTree builds the delegation tree starting from the given root agent ID.
func (s *Service) GetDelegationTree(rootID string) (*DelegationTree, error) {
	agent, err := s.store.GetAgent(rootID)
	if err != nil {
		return nil, fmt.Errorf("get root agent: %w", err)
	}
	return s.buildTree(agent)
}

func (s *Service) buildTree(agent *AgentIdentity) (*DelegationTree, error) {
	tree := &DelegationTree{
		Agent: agent,
	}
	children, err := s.store.GetChildAgents(agent.ID)
	if err != nil {
		return nil, err
	}
	for _, child := range children {
		childTree, err := s.buildTree(child)
		if err != nil {
			return nil, err
		}
		tree.Children = append(tree.Children, childTree)
	}
	return tree, nil
}
