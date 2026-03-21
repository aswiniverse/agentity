package delegation

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/agentity/agentity/internal/audit"
	"github.com/agentity/agentity/internal/identity"
	"github.com/agentity/agentity/internal/revocation"
	"github.com/agentity/agentity/pkg/token"
)

// DelegationRequest contains parameters for creating a delegation.
type DelegationRequest struct {
	ParentTokenEncoded string
	ChildAgentID       string
	Capabilities       []string
	Conditions         token.BlockConditions
	ParentAgentKey     ed25519.PrivateKey
}

// DelegationChain represents the chain of delegations for a token.
type DelegationChain struct {
	TokenID string       `json:"token_id"`
	Blocks  []ChainLink  `json:"blocks"`
	Depth   int          `json:"depth"`
}

// ChainLink represents a single link in a delegation chain.
type ChainLink struct {
	Index   int    `json:"index"`
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

// Engine manages delegation operations.
type Engine struct {
	identityStore identity.Store
	revocation    *revocation.Registry
	audit         *audit.Logger
	keyResolver   token.KeyResolver
}

// NewEngine creates a new delegation engine.
func NewEngine(store identity.Store, rev *revocation.Registry, auditLog *audit.Logger, keyResolver token.KeyResolver) *Engine {
	return &Engine{
		identityStore: store,
		revocation:    rev,
		audit:         auditLog,
		keyResolver:   keyResolver,
	}
}

// Delegate creates a new delegation by appending a block to the parent token.
func (e *Engine) Delegate(ctx context.Context, req DelegationRequest) (string, error) {
	// Verify the parent token first.
	checker := e.revocation.NewRevocationChecker(ctx)
	_, err := token.Verify(req.ParentTokenEncoded, e.keyResolver, checker)
	if err != nil {
		return "", fmt.Errorf("parent token verification failed: %w", err)
	}

	// Verify child agent exists and is active.
	childAgent, err := e.identityStore.GetAgent(req.ChildAgentID)
	if err != nil {
		return "", fmt.Errorf("get child agent: %w", err)
	}
	if childAgent.Status != identity.AgentStatusActive {
		return "", fmt.Errorf("child agent %s is not active (status: %s)", req.ChildAgentID, childAgent.Status)
	}

	// Decode parent token.
	parentACT, err := token.Decode(req.ParentTokenEncoded)
	if err != nil {
		return "", fmt.Errorf("decode parent token: %w", err)
	}

	// Perform delegation.
	delegatedACT, err := token.Delegate(parentACT, req.ChildAgentID, req.Capabilities, req.Conditions, req.ParentAgentKey)
	if err != nil {
		return "", fmt.Errorf("delegate token: %w", err)
	}

	// Encode the delegated token.
	encoded, err := token.Encode(delegatedACT)
	if err != nil {
		return "", fmt.Errorf("encode delegated token: %w", err)
	}

	// Log the delegation.
	lastBlock := parentACT.Blocks[len(parentACT.Blocks)-1]
	if e.audit != nil {
		_, _ = e.audit.LogWithToken(
			audit.EventTokenDelegated,
			lastBlock.Subject,
			req.ChildAgentID,
			"delegate",
			delegatedACT.TokenID,
			"success",
			map[string]interface{}{
				"capabilities": req.Capabilities,
				"chain_depth":  len(delegatedACT.Blocks),
			},
		)
	}

	return encoded, nil
}

// Verify verifies a token and returns the verified result.
func (e *Engine) Verify(ctx context.Context, encoded string) (*token.VerifiedACT, error) {
	checker := e.revocation.NewRevocationChecker(ctx)
	verified, err := token.Verify(encoded, e.keyResolver, checker)
	if err != nil {
		if e.audit != nil {
			_, _ = e.audit.Log(
				audit.EventAccessDenied,
				"unknown",
				"unknown",
				"verify",
				"denied",
				map[string]interface{}{
					"error": err.Error(),
				},
			)
		}
		return nil, err
	}

	if e.audit != nil {
		_, _ = e.audit.LogWithToken(
			audit.EventTokenVerified,
			verified.AgentID,
			verified.AgentID,
			"verify",
			verified.TokenID,
			"success",
			map[string]interface{}{
				"capabilities": verified.Capabilities,
				"chain_depth":  verified.ChainDepth,
			},
		)
	}

	return verified, nil
}

// GetChain returns the delegation chain for a token.
func (e *Engine) GetChain(_ context.Context, encoded string) (*DelegationChain, error) {
	act, err := token.Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode token: %w", err)
	}

	chain := &DelegationChain{
		TokenID: act.TokenID,
		Depth:   len(act.Blocks),
	}

	for _, block := range act.Blocks {
		chain.Blocks = append(chain.Blocks, ChainLink{
			Index:   block.Index,
			Issuer:  block.Issuer,
			Subject: block.Subject,
		})
	}

	return chain, nil
}
