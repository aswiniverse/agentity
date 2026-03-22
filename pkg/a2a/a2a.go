// Package a2a provides Agentity ACT token authentication middleware for
// Google's Agent-to-Agent (A2A) protocol.
//
// A2A requests are authenticated by verifying an AgentCapability Token (ACT)
// and checking that the token's effective capabilities include the capability
// required for the requested skill.
//
// Usage:
//
//	capMap := a2a.NewCapabilityMap().
//	    Map("web_search", "web_search").
//	    Map("code_execution", "code_exec")
//
//	auth := a2a.NewMiddleware(delegationEngine, capMap)
//	http.Handle("/a2a", auth.Handler(myA2AHandler))
package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/agentity/agentity/pkg/token"
)

// DelegationEngine is the interface used to verify ACT tokens.
// It matches the method signature of delegation.Engine.Verify.
type DelegationEngine interface {
	VerifyACT(ctx context.Context, encodedToken string) (*token.VerifiedACT, error)
}

// CapabilityMap maps A2A skill IDs to required ACT capabilities.
// A skill with no entry in the map defaults to requiring a capability with the
// same name as the skill ID (identity mapping).
type CapabilityMap struct {
	m map[string]string // skill ID → required ACT capability
}

// NewCapabilityMap creates an empty CapabilityMap.
func NewCapabilityMap() *CapabilityMap {
	return &CapabilityMap{m: make(map[string]string)}
}

// Map registers a skill-to-capability mapping. Returns the receiver for chaining.
func (cm *CapabilityMap) Map(skillID, requiredCapability string) *CapabilityMap {
	cm.m[skillID] = requiredCapability
	return cm
}

// required returns the ACT capability required for a skill. If no explicit
// mapping is registered, the skill ID itself is used as the capability.
func (cm *CapabilityMap) required(skillID string) string {
	if cap, ok := cm.m[skillID]; ok {
		return cap
	}
	return skillID
}

// A2AContext holds verified A2A request context.
type A2AContext struct {
	AgentID      string
	TaskID       string
	SkillID      string
	Capabilities []string // effective capabilities from ACT
}

// contextKey is the key type for values stored in request context.
type contextKey struct{}

// FromContext retrieves A2AContext from request context. Returns nil if not set.
func FromContext(ctx context.Context) *A2AContext {
	v, _ := ctx.Value(contextKey{}).(*A2AContext)
	return v
}

// a2aRequest represents an inbound A2A request body.
type a2aRequest struct {
	SkillID string          `json:"skill_id"`
	TaskID  string          `json:"task_id"`
	Input   json.RawMessage `json:"input,omitempty"`
}

// Middleware is the A2A ACT authentication middleware.
type Middleware struct {
	engine DelegationEngine
	capMap *CapabilityMap
}

// NewMiddleware creates a new A2A auth middleware.
func NewMiddleware(engine DelegationEngine, capMap *CapabilityMap) *Middleware {
	if capMap == nil {
		capMap = NewCapabilityMap()
	}
	return &Middleware{engine: engine, capMap: capMap}
}

// Handler wraps an A2A HTTP handler with ACT token authentication.
// The handler receives a context with the A2AContext available via FromContext().
//
// Token extraction: Authorization: Bearer <token> header.
// Skill and task IDs are extracted from the JSON request body.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the ACT token from the Authorization header.
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "missing token")
			return
		}
		encodedToken := strings.TrimPrefix(auth, "Bearer ")

		// Verify the token.
		act, err := m.engine.VerifyACT(r.Context(), encodedToken)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		// Parse the request body to extract skill_id and task_id.
		var skillID, taskID string
		if r.Body != nil {
			bodyBytes, err := io.ReadAll(r.Body)
			if err == nil && len(bodyBytes) > 0 {
				var req a2aRequest
				if json.Unmarshal(bodyBytes, &req) == nil {
					skillID = req.SkillID
					taskID = req.TaskID
				}
				// Restore body for downstream handler.
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}
		}

		// Determine required capability (default to skill ID if not mapped).
		required := m.capMap.required(skillID)

		// Check the required capability is present in the token.
		if !hasCapability(act.Capabilities, required) {
			writeCapabilityError(w, required)
			return
		}

		// Set A2AContext on request context and call next handler.
		a2aCtx := &A2AContext{
			AgentID:      act.AgentID,
			TaskID:       taskID,
			SkillID:      skillID,
			Capabilities: act.Capabilities,
		}
		ctx := context.WithValue(r.Context(), contextKey{}, a2aCtx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

// writeCapabilityError writes a JSON 403 error response for insufficient capabilities.
func writeCapabilityError(w http.ResponseWriter, required string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":    "insufficient capabilities",
		"required": required,
	})
}

// hasCapability reports whether caps contains the required capability.
func hasCapability(caps []string, required string) bool {
	for _, c := range caps {
		if c == required {
			return true
		}
	}
	return false
}
