package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/agentity/agentity/internal/delegation"
	"github.com/agentity/agentity/internal/identity"
	"github.com/agentity/agentity/internal/metrics"
	"github.com/agentity/agentity/internal/revocation"
	"github.com/go-chi/chi/v5"
)

// IdentityHandlers provides HTTP handlers for agent identity management.
type IdentityHandlers struct {
	service     *identity.Service
	revReg      *revocation.Registry
	keyResolver *delegation.KeyResolverImpl
}

// NewIdentityHandlers creates new identity handlers.
func NewIdentityHandlers(service *identity.Service, revReg *revocation.Registry, keyResolver *delegation.KeyResolverImpl) *IdentityHandlers {
	return &IdentityHandlers{service: service, revReg: revReg, keyResolver: keyResolver}
}

// RegisterAgent handles POST /api/v1/agents
func (h *IdentityHandlers) RegisterAgent(w http.ResponseWriter, r *http.Request) {
	var req identity.RegisterAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "Failed to parse request body: "+err.Error())
		return
	}

	agent, privateKey, err := h.service.RegisterAgent(req)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/registration-failed", "Registration Failed", err.Error())
		return
	}
	metrics.AgentsRegistered.Inc()

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"agent":       agent,
		"private_key": privateKey,
	})
}

// ListAgents handles GET /api/v1/agents
func (h *IdentityHandlers) ListAgents(w http.ResponseWriter, r *http.Request) {
	filter := identity.AgentFilter{
		Status:   identity.AgentStatus(r.URL.Query().Get("status")),
		ParentID: r.URL.Query().Get("parent_id"),
		Model:    r.URL.Query().Get("model"),
	}

	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil {
			filter.Limit = v
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil {
			filter.Offset = v
		}
	}

	agents, err := h.service.ListAgents(filter)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "https://agentity.dev/errors/internal", "Internal Error", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agents": agents,
		"count":  len(agents),
	})
}

// GetAgent handles GET /api/v1/agents/{id}
func (h *IdentityHandlers) GetAgent(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "Agent ID is required")
		return
	}

	// The URL param will have the UUID portion; reconstruct the full agent ID.
	agentID := "agent://" + id

	agent, err := h.service.GetAgent(agentID)
	if err != nil {
		writeProblem(w, http.StatusNotFound, "https://agentity.dev/errors/not-found", "Not Found", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, agent)
}

// GetDelegationTree handles GET /api/v1/agents/{id}/tree
func (h *IdentityHandlers) GetDelegationTree(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	agentID := "agent://" + id

	tree, err := h.service.GetDelegationTree(agentID)
	if err != nil {
		writeProblem(w, http.StatusNotFound, "https://agentity.dev/errors/not-found", "Not Found", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, tree)
}

// SuspendAgent handles POST /api/v1/agents/{id}/suspend
func (h *IdentityHandlers) SuspendAgent(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	agentID := "agent://" + id

	if err := h.service.SuspendAgent(agentID); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/suspend-failed", "Suspend Failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "suspended"})
}

// RevokeAgent handles POST /api/v1/agents/{id}/revoke
func (h *IdentityHandlers) RevokeAgent(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	agentID := "agent://" + id

	var req struct {
		Cascade bool `json:"cascade"`
	}
	// Body is optional; if not provided, cascade defaults to false.
	_ = json.NewDecoder(r.Body).Decode(&req)

	// Collect agents to revoke before updating the store so we have their IDs.
	// For cascade, get the full descendant list first.
	toRevoke := []string{agentID}
	if req.Cascade {
		if descendants, err := h.service.ListDescendants(agentID); err == nil {
			toRevoke = append(toRevoke, descendants...)
		}
	}

	if err := h.service.RevokeAgent(agentID, req.Cascade); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/revoke-failed", "Revoke Failed", err.Error())
		return
	}

	// Write every revoked agent ID to the revocation registry so that
	// token verification (which checks the registry, not the store) correctly
	// rejects tokens belonging to revoked agents across all instances.
	if h.revReg != nil {
		for _, aid := range toRevoke {
			if err := h.revReg.RevokeAgent(r.Context(), aid, "agent-revoked", req.Cascade); err != nil {
				writeProblem(w, http.StatusInternalServerError, "https://agentity.dev/errors/internal", "Revocation Failed", "Failed to write to revocation registry: "+err.Error())
				return
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// RotateKey handles POST /api/v1/agents/{id}/rotate-key
func (h *IdentityHandlers) RotateKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	agentID := "agent://" + id

	// Capture the old key ID before rotation so we can invalidate the cache.
	existingAgent, err := h.service.GetAgent(agentID)
	if err != nil {
		writeProblem(w, http.StatusNotFound, "https://agentity.dev/errors/not-found", "Not Found", err.Error())
		return
	}
	oldKeyID := existingAgent.KeyID

	agent, privateKey, err := h.service.RotateKey(agentID)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/rotate-failed", "Key Rotation Failed", err.Error())
		return
	}

	// Invalidate the cached public key so post-rotation verifications resolve the new key.
	if h.keyResolver != nil {
		h.keyResolver.InvalidateCache(oldKeyID)
	}

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent":       agent,
		"private_key": privateKey,
	})
}
