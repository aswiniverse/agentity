package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/agentity/agentity/internal/approval"
	"github.com/go-chi/chi/v5"
)

// ApprovalHandlers provides HTTP handlers for human approval gates.
type ApprovalHandlers struct {
	svc *approval.ApprovalService
}

// NewApprovalHandlers creates new approval handlers.
func NewApprovalHandlers(svc *approval.ApprovalService) *ApprovalHandlers {
	return &ApprovalHandlers{svc: svc}
}

// createApprovalRequest is the request body for POST /api/v1/approvals.
type createApprovalRequest struct {
	AgentID    string `json:"agent_id"`
	TokenID    string `json:"token_id"`
	Resource   string `json:"resource"`
	Reason     string `json:"reason"`
	WebhookURL string `json:"webhook_url"`
}

// CreateApproval handles POST /api/v1/approvals
func (h *ApprovalHandlers) CreateApproval(w http.ResponseWriter, r *http.Request) {
	var req createApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "Failed to parse request body: "+err.Error())
		return
	}

	if req.AgentID == "" || req.TokenID == "" || req.Resource == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "agent_id, token_id, and resource are required")
		return
	}

	ar, err := h.svc.RequestApproval(r.Context(), req.AgentID, req.TokenID, req.Resource, req.Reason, req.WebhookURL)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "https://agentity.dev/errors/internal", "Internal Error", err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":         ar.ID,
		"status":     string(ar.Status),
		"created_at": ar.CreatedAt,
	})
}

// decideApprovalRequest is the request body for approve/deny.
type decideApprovalRequest struct {
	ApproverID string `json:"approver_id"`
}

// ApproveApproval handles POST /api/v1/approvals/{id}/approve
func (h *ApprovalHandlers) ApproveApproval(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "approval id is required")
		return
	}

	var req decideApprovalRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // body is optional

	if err := h.svc.Approve(r.Context(), id, req.ApproverID); err != nil {
		if isNotFound(err) {
			writeProblem(w, http.StatusNotFound, "https://agentity.dev/errors/not-found", "Not Found", err.Error())
			return
		}
		if isAlreadyDecided(err) {
			writeProblem(w, http.StatusConflict, "https://agentity.dev/errors/already-decided", "Already Decided", err.Error())
			return
		}
		writeProblem(w, http.StatusInternalServerError, "https://agentity.dev/errors/internal", "Internal Error", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"id":     id,
		"status": string(approval.StatusApproved),
	})
}

// DenyApproval handles POST /api/v1/approvals/{id}/deny
func (h *ApprovalHandlers) DenyApproval(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "approval id is required")
		return
	}

	var req decideApprovalRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // body is optional

	if err := h.svc.Deny(r.Context(), id, req.ApproverID); err != nil {
		if isNotFound(err) {
			writeProblem(w, http.StatusNotFound, "https://agentity.dev/errors/not-found", "Not Found", err.Error())
			return
		}
		if isAlreadyDecided(err) {
			writeProblem(w, http.StatusConflict, "https://agentity.dev/errors/already-decided", "Already Decided", err.Error())
			return
		}
		writeProblem(w, http.StatusInternalServerError, "https://agentity.dev/errors/internal", "Internal Error", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"id":     id,
		"status": string(approval.StatusDenied),
	})
}

// ListApprovals handles GET /api/v1/approvals?agent_id={id}&status=pending
func (h *ApprovalHandlers) ListApprovals(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		writeProblem(w, http.StatusBadRequest, "https://agentity.dev/errors/invalid-request", "Invalid Request", "agent_id query parameter is required")
		return
	}

	approvals, err := h.svc.ListPending(r.Context(), agentID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "https://agentity.dev/errors/internal", "Internal Error", err.Error())
		return
	}

	if approvals == nil {
		approvals = []approval.ApprovalRequest{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"approvals": approvals,
	})
}

// isNotFound returns true if the error indicates a missing record.
func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found")
}

// isAlreadyDecided returns true if the error indicates the request was already decided.
func isAlreadyDecided(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already decided")
}
