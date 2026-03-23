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

// maxRevokeDepth caps cascade revocation to prevent stack overflows and
// runaway traversals in pathological delegation trees.
const maxRevokeDepth = 100

// revokeChildren iteratively revokes all descendants of parentID using BFS.
func (s *Service) revokeChildren(parentID string) error {
	type item struct {
		id    string
		depth int
	}
	queue := []item{{id: parentID, depth: 0}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		if cur.depth >= maxRevokeDepth {
			return fmt.Errorf("cascade revocation exceeded maximum depth (%d) at agent %s", maxRevokeDepth, cur.id)
		}

		children, err := s.store.GetChildAgents(cur.id)
		if err != nil {
			return err
		}
		for _, child := range children {
			child.Status = AgentStatusRevoked
			child.UpdatedAt = time.Now().UTC()
			if err := s.store.UpdateAgent(child); err != nil {
				return err
			}
			queue = append(queue, item{id: child.ID, depth: cur.depth + 1})
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

// ListDescendants returns all descendant agent IDs of the given agent (BFS, not including itself).
func (s *Service) ListDescendants(parentID string) ([]string, error) {
	var result []string
	queue := []string{parentID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		children, err := s.store.GetChildAgents(cur)
		if err != nil {
			return nil, err
		}
		for _, child := range children {
			result = append(result, child.ID)
			queue = append(queue, child.ID)
		}
	}
	return result, nil
}

// maxBuildTreeDepth caps delegation tree traversal to prevent stack overflows
// caused by deep or cyclic agent hierarchies.
const maxBuildTreeDepth = 100

// GetDelegationTree builds the delegation tree starting from the given root agent ID.
func (s *Service) GetDelegationTree(rootID string) (*DelegationTree, error) {
	agent, err := s.store.GetAgent(rootID)
	if err != nil {
		return nil, fmt.Errorf("get root agent: %w", err)
	}
	return s.buildTree(agent, 0)
}

func (s *Service) buildTree(agent *AgentIdentity, depth int) (*DelegationTree, error) {
	if depth >= maxBuildTreeDepth {
		return nil, fmt.Errorf("delegation tree exceeds maximum depth (%d) at agent %s", maxBuildTreeDepth, agent.ID)
	}
	tree := &DelegationTree{
		Agent: agent,
	}
	children, err := s.store.GetChildAgents(agent.ID)
	if err != nil {
		return nil, err
	}
	for _, child := range children {
		childTree, err := s.buildTree(child, depth+1)
		if err != nil {
			return nil, err
		}
		tree.Children = append(tree.Children, childTree)
	}
	return tree, nil
}
