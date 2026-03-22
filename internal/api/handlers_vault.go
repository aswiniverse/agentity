package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/agentity/agentity/internal/vault"
	"github.com/go-chi/chi/v5"
)

// VaultHandlers provides HTTP handlers for per-agent credential management.
type VaultHandlers struct {
	service *vault.VaultService
}

// NewVaultHandlers creates new vault handlers.
func NewVaultHandlers(service *vault.VaultService) *VaultHandlers {
	return &VaultHandlers{service: service}
}

// PutCredential handles POST /api/v1/agents/{id}/credentials
func (h *VaultHandlers) PutCredential(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	if agentID == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "Agent ID is required")
		return
	}

	var req struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "Failed to parse request body: "+err.Error())
		return
	}
	if req.Key == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "key is required")
		return
	}
	if req.Value == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "value is required")
		return
	}

	if err := h.service.Put(r.Context(), agentID, req.Key, req.Value); err != nil {
		writeProblem(w, http.StatusInternalServerError, "https://agentity.dev/errors/internal", "Internal Error", err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"agent_id": agentID,
		"key":      req.Key,
	})
}

// ListCredentials handles GET /api/v1/agents/{id}/credentials
func (h *VaultHandlers) ListCredentials(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	if agentID == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "Agent ID is required")
		return
	}

	keys, err := h.service.List(r.Context(), agentID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "https://agentity.dev/errors/internal", "Internal Error", err.Error())
		return
	}
	if keys == nil {
		keys = []string{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"keys": keys,
	})
}

// GetCredential handles GET /api/v1/agents/{id}/credentials/{key}
func (h *VaultHandlers) GetCredential(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	key := chi.URLParam(r, "key")
	if agentID == "" || key == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "Agent ID and key are required")
		return
	}

	value, err := h.service.Get(r.Context(), agentID, key)
	if err != nil {
		if isVaultNotFound(err) {
			writeProblem(w, http.StatusNotFound, "https://agentity.dev/errors/not-found", "Not Found", err.Error())
			return
		}
		writeProblem(w, http.StatusInternalServerError, "https://agentity.dev/errors/internal", "Internal Error", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"key":   key,
		"value": value,
	})
}

// DeleteCredential handles DELETE /api/v1/agents/{id}/credentials/{key}
func (h *VaultHandlers) DeleteCredential(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	key := chi.URLParam(r, "key")
	if agentID == "" || key == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "Agent ID and key are required")
		return
	}

	if err := h.service.Delete(r.Context(), agentID, key); err != nil {
		if isVaultNotFound(err) {
			writeProblem(w, http.StatusNotFound, "https://agentity.dev/errors/not-found", "Not Found", err.Error())
			return
		}
		writeProblem(w, http.StatusInternalServerError, "https://agentity.dev/errors/internal", "Internal Error", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// isVaultNotFound returns true if the error message indicates a not-found condition
// from the vault store (both MemoryVaultStore and PostgresVaultStore use this pattern).
func isVaultNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "credential not found") ||
		strings.Contains(msg, "no rows in result set")
}
