package api

import (
	"encoding/json"
	"net/http"

	"github.com/agentity/agentity/internal/user"
	"github.com/go-chi/chi/v5"
)

// UserHandlers provides HTTP handlers for user-agent binding operations.
type UserHandlers struct {
	userService *user.UserService
}

// NewUserHandlers creates new user handlers.
func NewUserHandlers(userService *user.UserService) *UserHandlers {
	return &UserHandlers{userService: userService}
}

// BindUserRequest is the request body for binding a user to an agent.
type BindUserRequest struct {
	OIDCToken string   `json:"oidc_token"`
	AgentID   string   `json:"agent_id"`
	Scopes    []string `json:"scopes"`
}

// BindUser handles POST /api/v1/users/bind
func (h *UserHandlers) BindUser(w http.ResponseWriter, r *http.Request) {
	var req BindUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "Failed to parse request body: "+err.Error())
		return
	}

	if req.OIDCToken == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "oidc_token is required")
		return
	}
	if req.AgentID == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "agent_id is required")
		return
	}

	binding, err := h.userService.BindUserToAgent(r.Context(), req.OIDCToken, req.AgentID, req.Scopes)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/binding-failed", "Binding Failed", err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"binding_id": binding.ID,
		"user_id":    binding.UserID,
		"agent_id":   binding.AgentID,
		"scopes":     binding.Scopes,
	})
}

// ListUserAgents handles GET /api/v1/users/{id}/agents
func (h *UserHandlers) ListUserAgents(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	if userID == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "User ID is required")
		return
	}

	bindings, err := h.userService.ListUserAgents(r.Context(), userID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "https://agentity.dev/errors/internal", "Internal Error", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"bindings": bindings,
		"count":    len(bindings),
	})
}

// RevokeUserAgent handles DELETE /api/v1/users/{id}/agents/{agent_id}
func (h *UserHandlers) RevokeUserAgent(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	agentID := chi.URLParam(r, "agent_id")

	if userID == "" || agentID == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "User ID and Agent ID are required")
		return
	}

	if err := h.userService.RevokeBinding(r.Context(), userID, agentID); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/revoke-failed", "Revoke Failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// RegisterOIDCProviderRequest is the request body for registering an OIDC provider.
type RegisterOIDCProviderRequest struct {
	IssuerURL string `json:"issuer_url"`
	ClientID  string `json:"client_id"`
	JWKSURL   string `json:"jwks_url"`
}

// RegisterOIDCProvider handles POST /api/v1/admin/oidc-providers
func (h *UserHandlers) RegisterOIDCProvider(w http.ResponseWriter, r *http.Request) {
	var req RegisterOIDCProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "Failed to parse request body: "+err.Error())
		return
	}

	if req.IssuerURL == "" || req.ClientID == "" || req.JWKSURL == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "issuer_url, client_id, and jwks_url are required")
		return
	}

	provider := &user.OIDCProvider{
		IssuerURL: req.IssuerURL,
		ClientID:  req.ClientID,
		JWKSURL:   req.JWKSURL,
		Enabled:   true,
	}

	if err := h.userService.Store().CreateOIDCProvider(r.Context(), provider); err != nil {
		writeProblem(w, http.StatusInternalServerError, "https://agentity.dev/errors/internal", "Internal Error", err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":         provider.ID,
		"issuer_url": provider.IssuerURL,
		"client_id":  provider.ClientID,
	})
}
