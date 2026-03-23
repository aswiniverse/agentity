package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/agentity/agentity/internal/audit"
	"github.com/agentity/agentity/internal/delegation"
	"github.com/agentity/agentity/internal/identity"
	"github.com/agentity/agentity/internal/metrics"
	"github.com/agentity/agentity/internal/policy"
	"github.com/agentity/agentity/internal/revocation"
	"github.com/agentity/agentity/internal/user"
	agcrypto "github.com/agentity/agentity/pkg/crypto"
	"github.com/agentity/agentity/pkg/token"
)

// TokenHandlers provides HTTP handlers for token operations.
type TokenHandlers struct {
	rootKeyStore     *agcrypto.RootKeyStore
	delegationEngine *delegation.Engine
	revocationReg    *revocation.Registry
	auditLogger      *audit.Logger
	identityService  *identity.Service
	policyEngine     *policy.Engine
	userService      *user.UserService
	agentLimiter     *AgentRateLimiter
}

// NewTokenHandlers creates new token handlers.
func NewTokenHandlers(
	rootKeyStore *agcrypto.RootKeyStore,
	engine *delegation.Engine,
	rev *revocation.Registry,
	auditLog *audit.Logger,
	idService *identity.Service,
	policyEngine *policy.Engine,
	userSvc *user.UserService,
) *TokenHandlers {
	return &TokenHandlers{
		rootKeyStore:     rootKeyStore,
		delegationEngine: engine,
		revocationReg:    rev,
		auditLogger:      auditLog,
		identityService:  idService,
		policyEngine:     policyEngine,
		userService:      userSvc,
		// 20 token operations per second per agent.
		agentLimiter: NewAgentRateLimiter(20, time.Second),
	}
}

// IssueTokenRequest is the request body for issuing a root token.
type IssueTokenRequest struct {
	AgentID      string               `json:"agent_id"`
	Capabilities []string             `json:"capabilities"`
	Conditions   token.BlockConditions `json:"conditions"`
	UserToken    string               `json:"user_token,omitempty"`
}

// IssueToken handles POST /api/v1/tokens/issue
// M9 fix: verifies agent exists and is active before issuing.
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

	// Per-agent rate limit check.
	if !h.agentLimiter.Allow(req.AgentID) {
		writeProblem(w, http.StatusTooManyRequests, "https://agentity.dev/errors/rate-limited", "Rate Limited", "Too many requests for this agent. Please slow down.")
		return
	}

	// M9: verify agent exists and is active before issuing a token for it.
	agent, err := h.identityService.GetAgent(req.AgentID)
	if err != nil {
		writeProblem(w, http.StatusNotFound, "https://agentity.dev/errors/agent-not-found", "Agent Not Found", "Agent not found: "+req.AgentID)
		return
	}
	if agent.Status != identity.AgentStatusActive {
		writeProblem(w, http.StatusForbidden, "https://agentity.dev/errors/agent-not-active", "Agent Not Active", "Agent is "+string(agent.Status)+", cannot issue token")
		return
	}

	// Evaluate policies before issuing.
	if h.policyEngine != nil {
		allowed, policyName, err := h.policyEngine.Evaluate(r.Context(), policy.PolicyInput{
			AgentID:      req.AgentID,
			AgentModel:   agent.Fingerprint.Model,
			Capabilities: req.Capabilities,
			Action:       "issue",
			ExpiresAt:    req.Conditions.ExpiresAt,
		})
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "https://agentity.dev/errors/internal", "Internal Error", "Policy evaluation failed: "+err.Error())
			return
		}
		if !allowed {
			metrics.PolicyDenials.Inc()
			detail := "Denied by policy"
			if policyName != "" {
				detail = "Denied by policy: " + policyName
			}
			writeProblem(w, http.StatusForbidden, "https://agentity.dev/errors/policy-denied", "Policy Denied", detail)
			return
		}
	}

	// If a user token is provided, verify OIDC token and check user-agent binding.
	var userID string
	if req.UserToken != "" && h.userService != nil {
		oidcUser, err := h.userService.VerifyUserToken(r.Context(), req.UserToken)
		if err != nil {
			writeProblem(w, http.StatusUnauthorized, "https://agentity.dev/errors/user-token-invalid", "User Token Invalid", err.Error())
			return
		}
		// Look up user by external ID to get the internal user ID.
		store := h.userService.Store()
		existingUser, err := store.GetUserByExternalID(r.Context(), oidcUser.ExternalID, oidcUser.Issuer)
		if err != nil {
			writeProblem(w, http.StatusForbidden, "https://agentity.dev/errors/user-not-found", "User Not Found", "User not registered")
			return
		}
		// Check binding exists.
		_, err = store.GetBinding(r.Context(), existingUser.ID, req.AgentID)
		if err != nil {
			writeProblem(w, http.StatusForbidden, "https://agentity.dev/errors/no-binding", "No Binding", "No active binding between user and agent")
			return
		}
		userID = existingUser.ID
	}

	issueStart := time.Now()
	act, err := token.IssueRootTokenWithOptions(req.AgentID, req.Capabilities, req.Conditions, h.rootKeyStore.PrivateKey(), token.RootTokenOptions{
		UserID:           userID,
		SystemPromptHash: agent.Fingerprint.SystemPromptHash,
		ToolFingerprint:  agent.Fingerprint.ToolFingerprint,
	})
	metrics.IssuanceDuration.Observe(time.Since(issueStart).Seconds())
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/token-issue-failed", "Token Issue Failed", err.Error())
		return
	}

	metrics.TokensIssued.Inc()

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
			map[string]interface{}{"capabilities": req.Capabilities},
		)
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"token":    encoded,
		"token_id": act.TokenID,
	})
}

// SubmitDelegatedTokenRequest accepts a pre-signed delegated ACT token for
// server-side validation and audit logging.
//
// C4 fix: delegation signing now happens client-side (using the Go SDK's
// DelegateTokenLocally method). The server never receives agent private keys.
// The agent signs the new delegation block locally and submits the full
// encoded token for verification and audit recording only.
type SubmitDelegatedTokenRequest struct {
	DelegatedToken string `json:"delegated_token"` // pre-signed by the parent agent locally
}

// SubmitDelegatedToken handles POST /api/v1/tokens/delegate
func (h *TokenHandlers) SubmitDelegatedToken(w http.ResponseWriter, r *http.Request) {
	var req SubmitDelegatedTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "Failed to parse request body: "+err.Error())
		return
	}

	if req.DelegatedToken == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "delegated_token is required")
		return
	}

	// Verify the pre-signed delegated token: checks all signatures, capability
	// attenuation, expiry, revocation.
	verified, err := h.delegationEngine.Verify(r.Context(), req.DelegatedToken)
	if err != nil {
		metrics.TokensRejected.Inc()
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/delegation-invalid", "Delegation Invalid", err.Error())
		return
	}
	metrics.TokensDelegated.Inc()

	if h.auditLogger != nil {
		_, _ = h.auditLogger.LogWithToken(
			audit.EventTokenDelegated,
			verified.DelegationPath[max(0, len(verified.DelegationPath)-2)],
			verified.AgentID,
			"delegate",
			verified.TokenID,
			"success",
			map[string]interface{}{
				"capabilities": verified.Capabilities,
				"chain_depth":  verified.ChainDepth,
			},
		)
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"token":    req.DelegatedToken,
		"token_id": verified.TokenID,
		"verified": verified,
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

	// Cheap decode to extract agent ID for rate limiting before expensive crypto verify.
	if decoded, decodeErr := token.Decode(req.Token); decodeErr == nil && len(decoded.Blocks) > 0 {
		agentID := decoded.Blocks[0].Subject
		if !h.agentLimiter.Allow(agentID) {
			writeProblem(w, http.StatusTooManyRequests, "https://agentity.dev/errors/rate-limited", "Rate Limited", "Too many verification requests for this agent. Please slow down.")
			return
		}
	}

	verifyStart := time.Now()
	verified, err := h.delegationEngine.Verify(r.Context(), req.Token)
	metrics.VerificationDuration.Observe(time.Since(verifyStart).Seconds())
	if err != nil {
		metrics.TokensRejected.Inc()
		writeProblem(w, http.StatusUnauthorized, "https://agentity.dev/errors/token-invalid", "Token Invalid", err.Error())
		return
	}

	// Evaluate policies on the verified token.
	if h.policyEngine != nil {
		allowed, policyName, err := h.policyEngine.Evaluate(r.Context(), policy.PolicyInput{
			AgentID:      verified.AgentID,
			Capabilities: verified.Capabilities,
			ChainDepth:   verified.ChainDepth,
			Action:       "verify",
		})
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "https://agentity.dev/errors/internal", "Internal Error", "Policy evaluation failed: "+err.Error())
			return
		}
		if !allowed {
			metrics.PolicyDenials.Inc()
			detail := "Denied by policy"
			if policyName != "" {
				detail = "Denied by policy: " + policyName
			}
			writeProblem(w, http.StatusForbidden, "https://agentity.dev/errors/policy-denied", "Policy Denied", detail)
			return
		}
	}
	metrics.TokensVerified.Inc()

	writeJSON(w, http.StatusOK, verified)
}

// RevokeTokenRequest is the request body for revoking a token.
type RevokeTokenRequest struct {
	TokenID string `json:"token_id"`
	Reason  string `json:"reason"`
}

// RevokeToken handles POST /api/v1/tokens/revoke
// Minor fix: use r.Context() instead of context.Background() for proper cancellation.
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

	if err := h.revocationReg.RevokeToken(r.Context(), req.TokenID, req.Reason); err != nil {
		writeProblem(w, http.StatusInternalServerError, "https://agentity.dev/errors/internal", "Internal Error", err.Error())
		return
	}
	metrics.TokensRevoked.Inc()

	if h.auditLogger != nil {
		_, _ = h.auditLogger.LogWithToken(
			audit.EventTokenRevoked,
			"admin",
			req.TokenID,
			"revoke",
			req.TokenID,
			"success",
			map[string]interface{}{"reason": req.Reason},
		)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// GetChain handles GET /api/v1/tokens/{id}/chain
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
