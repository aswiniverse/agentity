package api

import (
	"encoding/json"
	"net/http"

	"github.com/agentity/agentity/internal/audit"
	"github.com/agentity/agentity/internal/identity"
	"github.com/agentity/agentity/internal/policy"
	"github.com/agentity/agentity/internal/revocation"
	"github.com/go-chi/chi/v5"
)

// AdminHandlers provides admin management endpoints.
type AdminHandlers struct {
	identityService *identity.Service
	policyEngine    *policy.Engine
	revocationReg   *revocation.Registry
	auditLogger     *audit.Logger
}

// NewAdminHandlers creates new admin handlers.
func NewAdminHandlers(idSvc *identity.Service, pe *policy.Engine, rev *revocation.Registry, auditLog *audit.Logger) *AdminHandlers {
	return &AdminHandlers{
		identityService: idSvc,
		policyEngine:    pe,
		revocationReg:   rev,
		auditLogger:     auditLog,
	}
}

// Stats handles GET /api/v1/admin/stats
func (h *AdminHandlers) Stats(w http.ResponseWriter, r *http.Request) {
	agents, _ := h.identityService.ListAgents(identity.AgentFilter{Limit: 1000})
	agentCount := len(agents)

	activeCount := 0
	revokedCount := 0
	suspendedCount := 0
	for _, a := range agents {
		switch a.Status {
		case identity.AgentStatusActive:
			activeCount++
		case identity.AgentStatusRevoked:
			revokedCount++
		case identity.AgentStatusSuspended:
			suspendedCount++
		}
	}

	policies := h.policyEngine.ListPolicies()
	tokenRevocations := h.revocationReg.ListTokenRevocations()
	agentRevocations := h.revocationReg.ListAgentRevocations()

	auditCount := 0
	if h.auditLogger != nil {
		auditCount = h.auditLogger.Count()
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agents": map[string]int{
			"total":     agentCount,
			"active":    activeCount,
			"revoked":   revokedCount,
			"suspended": suspendedCount,
		},
		"policies":          len(policies),
		"token_revocations": len(tokenRevocations),
		"agent_revocations": len(agentRevocations),
		"audit_entries":     auditCount,
	})
}

// CreatePolicyRequest is the request body for creating a policy.
type CreatePolicyRequest struct {
	Name       string `json:"name"`
	Expression string `json:"expression"`
	Action     string `json:"action"`
	Priority   int    `json:"priority"`
}

// ListPolicies handles GET /api/v1/admin/policies
func (h *AdminHandlers) ListPolicies(w http.ResponseWriter, _ *http.Request) {
	policies := h.policyEngine.ListPolicies()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"policies": policies,
		"count":    len(policies),
	})
}

// CreatePolicy handles POST /api/v1/admin/policies
func (h *AdminHandlers) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	var req CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "Failed to parse request body: "+err.Error())
		return
	}

	if req.Name == "" || req.Expression == "" || req.Action == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "name, expression, and action are required")
		return
	}

	p, err := h.policyEngine.AddPolicy(req.Name, req.Expression, req.Action, req.Priority)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/policy-invalid", "Invalid Policy", err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, p)
}

// DeletePolicy handles DELETE /api/v1/admin/policies/{id}
func (h *AdminHandlers) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "Policy ID is required")
		return
	}

	if err := h.policyEngine.RemovePolicy(id); err != nil {
		writeProblem(w, http.StatusNotFound, "https://agentity.dev/errors/not-found", "Not Found", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ListRevocations handles GET /api/v1/admin/revocations
func (h *AdminHandlers) ListRevocations(w http.ResponseWriter, _ *http.Request) {
	tokenRevocations := h.revocationReg.ListTokenRevocations()
	agentRevocations := h.revocationReg.ListAgentRevocations()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token_revocations": tokenRevocations,
		"agent_revocations": agentRevocations,
	})
}
