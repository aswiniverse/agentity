package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/agentity/agentity/internal/audit"
	"github.com/agentity/agentity/internal/delegation"
	"github.com/agentity/agentity/internal/revocation"
	agcrypto "github.com/agentity/agentity/pkg/crypto"
	"github.com/agentity/agentity/pkg/token"
)

// TokenHandlers provides HTTP handlers for token operations.
type TokenHandlers struct {
	rootKeyStore     *agcrypto.RootKeyStore
	delegationEngine *delegation.Engine
	revocationReg    *revocation.Registry
	auditLogger      *audit.Logger
}

// NewTokenHandlers creates new token handlers.
func NewTokenHandlers(rootKeyStore *agcrypto.RootKeyStore, engine *delegation.Engine, rev *revocation.Registry, auditLog *audit.Logger) *TokenHandlers {
	return &TokenHandlers{
		rootKeyStore:     rootKeyStore,
		delegationEngine: engine,
		revocationReg:    rev,
		auditLogger:      auditLog,
	}
}

// IssueTokenRequest is the request body for issuing a root token.
type IssueTokenRequest struct {
	AgentID      string               `json:"agent_id"`
	Capabilities []string             `json:"capabilities"`
	Conditions   token.BlockConditions `json:"conditions"`
}

// IssueToken handles POST /api/v1/tokens/issue
func (h *TokenHandlers) IssueToken(w http.ResponseWriter, r *http.Request) {
	var req IssueTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "Failed to parse request body: "+err.Error())
		return
	}

	if req.AgentID == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "agent_id is required")
		return
	}
	if len(req.Capabilities) == 0 {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "capabilities must not be empty")
		return
	}

	act, err := token.IssueRootToken(req.AgentID, req.Capabilities, req.Conditions, h.rootKeyStore.PrivateKey())
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/token-issue-failed", "Token Issue Failed", err.Error())
		return
	}

	encoded, err := token.Encode(act)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "https://agentity.dev/errors/internal", "Internal Error", err.Error())
		return
	}

	if h.auditLogger != nil {
		_, _ = h.auditLogger.LogWithToken(
			audit.EventTokenIssued,
			"agentity://server",
			req.AgentID,
			"issue",
			act.TokenID,
			"success",
			map[string]interface{}{
				"capabilities": req.Capabilities,
			},
		)
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"token":    encoded,
		"token_id": act.TokenID,
	})
}

// DelegateTokenRequest is the request body for delegating a token.
type DelegateTokenRequest struct {
	ParentToken    string               `json:"parent_token"`
	ChildAgentID   string               `json:"child_agent_id"`
	Capabilities   []string             `json:"capabilities"`
	Conditions     token.BlockConditions `json:"conditions"`
	ParentAgentKey string               `json:"parent_agent_key"` // base64url-encoded private key
}

// DelegateToken handles POST /api/v1/tokens/delegate
func (h *TokenHandlers) DelegateToken(w http.ResponseWriter, r *http.Request) {
	var req DelegateTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "Failed to parse request body: "+err.Error())
		return
	}

	if req.ParentToken == "" || req.ChildAgentID == "" || req.ParentAgentKey == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "parent_token, child_agent_id, and parent_agent_key are required")
		return
	}

	privKey, err := agcrypto.DecodePrivateKeyBase64(req.ParentAgentKey)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-key", "Invalid Key", "Failed to decode parent_agent_key: "+err.Error())
		return
	}

	delegReq := delegation.DelegationRequest{
		ParentTokenEncoded: req.ParentToken,
		ChildAgentID:       req.ChildAgentID,
		Capabilities:       req.Capabilities,
		Conditions:         req.Conditions,
		ParentAgentKey:     privKey,
	}

	encoded, err := h.delegationEngine.Delegate(r.Context(), delegReq)
	if err != nil {
		writeProblem(w, http.StatusForbidden, "https://agentity.dev/errors/capability-amplification", "Delegation Failed", err.Error())
		return
	}

	// Decode to get token ID.
	act, _ := token.Decode(encoded)
	tokenID := ""
	if act != nil {
		tokenID = act.TokenID
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"token":    encoded,
		"token_id": tokenID,
	})
}

// VerifyTokenRequest is the request body for verifying a token.
type VerifyTokenRequest struct {
	Token string `json:"token"`
}

// VerifyToken handles POST /api/v1/tokens/verify
func (h *TokenHandlers) VerifyToken(w http.ResponseWriter, r *http.Request) {
	var req VerifyTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "Failed to parse request body: "+err.Error())
		return
	}

	if req.Token == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "token is required")
		return
	}

	verified, err := h.delegationEngine.Verify(r.Context(), req.Token)
	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "https://agentity.dev/errors/token-invalid", "Token Invalid", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, verified)
}

// RevokeTokenRequest is the request body for revoking a token.
type RevokeTokenRequest struct {
	TokenID string `json:"token_id"`
	Reason  string `json:"reason"`
}

// RevokeToken handles POST /api/v1/tokens/revoke
func (h *TokenHandlers) RevokeToken(w http.ResponseWriter, r *http.Request) {
	var req RevokeTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "Failed to parse request body: "+err.Error())
		return
	}

	if req.TokenID == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "token_id is required")
		return
	}

	if err := h.revocationReg.RevokeToken(context.Background(), req.TokenID, req.Reason); err != nil {
		writeProblem(w, http.StatusInternalServerError, "https://agentity.dev/errors/internal", "Internal Error", err.Error())
		return
	}

	if h.auditLogger != nil {
		_, _ = h.auditLogger.LogWithToken(
			audit.EventTokenRevoked,
			"admin",
			req.TokenID,
			"revoke",
			req.TokenID,
			"success",
			map[string]interface{}{
				"reason": req.Reason,
			},
		)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// GetChain handles GET /api/v1/tokens/{id}/chain
// Note: for simplicity, this endpoint expects the full encoded token as a query parameter.
func (h *TokenHandlers) GetChain(w http.ResponseWriter, r *http.Request) {
	encodedToken := r.URL.Query().Get("token")
	if encodedToken == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "token query parameter is required")
		return
	}

	chain, err := h.delegationEngine.GetChain(r.Context(), encodedToken)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-token", "Invalid Token", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, chain)
}
