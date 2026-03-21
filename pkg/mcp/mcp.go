// Package mcp provides Agentity ACT token authentication middleware for
// MCP (Model Context Protocol) servers.
//
// MCP tool calls are authenticated by verifying an AgentCapability Token (ACT)
// and checking that the token's effective capabilities include the capability
// required for the requested tool.
//
// Usage (HTTP MCP server):
//
//	capMap := mcp.NewToolCapabilityMap().
//	    Map("read_file", "read_file").
//	    Map("write_file", "write_file").
//	    Map("execute_code", "code_exec")
//
//	auth := mcp.NewMiddleware(delegationEngine, capMap)
//	http.Handle("/mcp/call", auth.Handler(myMCPHandler))
//
// Usage (stdio / in-process):
//
//	result, err := mcp.VerifyToolCall(ctx, delegationEngine, encodedToken, "read_file", capMap)
//	if err != nil { /* denied */ }
//	// result.AgentID, result.Capabilities are available
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/agentity/agentity/internal/delegation"
	"github.com/agentity/agentity/pkg/token"
)

// ToolCapabilityMap maps MCP tool names to the ACT capability required to call them.
// A tool with no entry in the map defaults to requiring a capability with the
// same name as the tool (identity mapping).
type ToolCapabilityMap struct {
	m map[string]string // tool name → required ACT capability
}

// NewToolCapabilityMap creates an empty map.
func NewToolCapabilityMap() *ToolCapabilityMap {
	return &ToolCapabilityMap{m: make(map[string]string)}
}

// Map registers a tool-to-capability mapping. Returns the receiver for chaining.
func (tcm *ToolCapabilityMap) Map(toolName, requiredCapability string) *ToolCapabilityMap {
	tcm.m[toolName] = requiredCapability
	return tcm
}

// Required returns the ACT capability required for a tool. If no explicit
// mapping is registered, the tool name itself is used as the capability.
func (tcm *ToolCapabilityMap) Required(toolName string) string {
	if cap, ok := tcm.m[toolName]; ok {
		return cap
	}
	// Default: capability name equals tool name.
	return toolName
}

// AuthResult holds the verified claims extracted from a valid ACT token.
type AuthResult struct {
	AgentID      string
	Capabilities []string
	ChainDepth   int
	TokenID      string
}

// MCPRequest represents an inbound MCP tool call request.
// The JSON structure matches the MCP protocol's "call_tool" message format.
type MCPRequest struct {
	// Tool is the name of the MCP tool being called.
	Tool string `json:"tool"`
	// Token is the base64url-encoded ACT token, provided by the calling agent.
	// Can alternatively be supplied in the Authorization header as "Bearer <token>".
	Token string `json:"token,omitempty"`
	// Params are the tool-specific input parameters (passed through unchanged).
	Params json.RawMessage `json:"params,omitempty"`
}

// contextKey is the key type for values stored in request context.
type contextKey string

const authResultKey contextKey = "mcp_auth_result"

// AuthResultFromContext retrieves the AuthResult stored by the middleware.
// Returns nil if the middleware did not run or authentication failed.
func AuthResultFromContext(ctx context.Context) *AuthResult {
	v, _ := ctx.Value(authResultKey).(*AuthResult)
	return v
}

// VerifyToolCall verifies an ACT token for a specific tool call.
// It is the core verification function used by both the HTTP middleware and
// in-process / stdio MCP adapters.
//
// Returns AuthResult on success, or an error describing why access was denied.
func VerifyToolCall(
	ctx context.Context,
	engine *delegation.Engine,
	encodedToken string,
	toolName string,
	capMap *ToolCapabilityMap,
) (*AuthResult, error) {
	if encodedToken == "" {
		return nil, fmt.Errorf("missing ACT token")
	}

	// Verify signature chain, expiry, and revocation status.
	verified, err := engine.Verify(ctx, encodedToken)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// Check the required capability for this tool.
	required := capMap.Required(toolName)
	if !hasCapability(verified.Capabilities, required) {
		return nil, fmt.Errorf(
			"agent %s does not have capability %q required for tool %q (has: %v)",
			verified.AgentID, required, toolName, verified.Capabilities,
		)
	}

	return &AuthResult{
		AgentID:      verified.AgentID,
		Capabilities: verified.Capabilities,
		ChainDepth:   verified.ChainDepth,
		TokenID:      verified.TokenID,
	}, nil
}

// Middleware provides HTTP middleware for MCP server authentication.
type Middleware struct {
	engine *delegation.Engine
	capMap *ToolCapabilityMap
}

// NewMiddleware creates a new MCP auth middleware.
func NewMiddleware(engine *delegation.Engine, capMap *ToolCapabilityMap) *Middleware {
	if capMap == nil {
		capMap = NewToolCapabilityMap()
	}
	return &Middleware{engine: engine, capMap: capMap}
}

// Handler wraps an MCP HTTP handler with ACT token authentication.
// The handler receives a context with the AuthResult available via
// AuthResultFromContext().
//
// Token extraction order:
//  1. Authorization: Bearer <token> header
//  2. "token" field in the JSON request body
//
// The tool name is extracted from the "tool" field of the JSON body.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the ACT token from the Authorization header first.
		encodedToken := ""
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			encodedToken = strings.TrimPrefix(auth, "Bearer ")
		}

		// Parse the request body to get tool name and fallback token.
		var req MCPRequest
		if r.Body != nil && r.Header.Get("Content-Type") == "application/json" {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeMCPError(w, http.StatusBadRequest, "invalid_request", "Failed to parse MCP request body: "+err.Error())
				return
			}
			// Restore the body so the downstream handler can re-read params.
			// We've already extracted what we need; params are in req.Params.
			r = r.WithContext(context.WithValue(r.Context(), contextKey("mcp_params"), req.Params))
			if encodedToken == "" {
				encodedToken = req.Token
			}
		}

		if req.Tool == "" {
			// Fallback: read tool name from X-MCP-Tool header.
			req.Tool = r.Header.Get("X-MCP-Tool")
		}
		if req.Tool == "" {
			writeMCPError(w, http.StatusBadRequest, "missing_tool", "MCP tool name is required (JSON field 'tool' or X-MCP-Tool header)")
			return
		}

		result, err := VerifyToolCall(r.Context(), m.engine, encodedToken, req.Tool, m.capMap)
		if err != nil {
			writeMCPError(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}

		// Store auth result in context for the downstream handler.
		ctx := context.WithValue(r.Context(), authResultKey, result)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// writeMCPError writes a JSON error response compatible with the MCP protocol.
func writeMCPError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   code,
		"message": message,
	})
}

func hasCapability(caps []string, required string) bool {
	for _, c := range caps {
		if c == required {
			return true
		}
	}
	return false
}

// MCPParamsFromContext retrieves the raw MCP params JSON from the context,
// set by the middleware after parsing the request body.
func MCPParamsFromContext(ctx context.Context) json.RawMessage {
	v, _ := ctx.Value(contextKey("mcp_params")).(json.RawMessage)
	return v
}

// TokenToMCPClaims decodes an ACT token without verifying it, for inspection.
// For full verification use VerifyToolCall instead.
func TokenToMCPClaims(encodedToken string) (*token.VerifiedACT, error) {
	act, err := token.Decode(encodedToken)
	if err != nil {
		return nil, fmt.Errorf("decode token: %w", err)
	}
	if len(act.Blocks) == 0 {
		return nil, fmt.Errorf("token has no blocks")
	}
	last := act.Blocks[len(act.Blocks)-1]
	return &token.VerifiedACT{
		TokenID:      act.TokenID,
		AgentID:      last.Subject,
		Capabilities: last.Capabilities,
		ExpiresAt:    last.Conditions.ExpiresAt,
		ChainDepth:   len(act.Blocks),
	}, nil
}
