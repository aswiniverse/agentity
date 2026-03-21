package api

import (
	"net/http"
	"strconv"

	"github.com/agentity/agentity/internal/audit"
)

// AuditHandlers provides HTTP handlers for audit log queries.
type AuditHandlers struct {
	logger *audit.Logger
}

// NewAuditHandlers creates new audit handlers.
func NewAuditHandlers(logger *audit.Logger) *AuditHandlers {
	return &AuditHandlers{logger: logger}
}

// ListAuditEntries handles GET /api/v1/audit
func (h *AuditHandlers) ListAuditEntries(w http.ResponseWriter, r *http.Request) {
	filter := audit.AuditFilter{
		ActorID:  r.URL.Query().Get("actor_id"),
		TargetID: r.URL.Query().Get("target_id"),
		Type:     r.URL.Query().Get("type"),
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

	entries := h.logger.List(filter)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
	})
}
