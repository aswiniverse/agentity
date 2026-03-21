package api

import (
	"encoding/json"
	"net/http"
)

// openAPISpec is the OpenAPI 3.1 specification for the Agentity API.
// Served at GET /api/v1/openapi.json (no auth required).
var openAPISpec = map[string]interface{}{
	"openapi": "3.1.0",
	"info": map[string]interface{}{
		"title":       "Agentity API",
		"description": "Open-source IAM system for AI agents. Provides agent identity management, AgentCapability Token (ACT) issuance and delegation, CEL policy enforcement, and OAuth2.1/OIDC compatibility.",
		"version":     "1.0.0",
		"license":     map[string]string{"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
		"contact":     map[string]string{"name": "Agentity", "url": "https://github.com/agentity/agentity"},
	},
	"servers": []map[string]interface{}{
		{"url": "http://localhost:8080", "description": "Local development"},
	},
	"security": []map[string]interface{}{
		{"AdminAPIKey": []string{}},
	},
	"components": map[string]interface{}{
		"securitySchemes": map[string]interface{}{
			"AdminAPIKey": map[string]interface{}{
				"type": "apiKey",
				"in":   "header",
				"name": "X-Admin-API-Key",
			},
		},
		"schemas": map[string]interface{}{
			"Problem": map[string]interface{}{
				"type":        "object",
				"description": "RFC 7807 Problem Details",
				"properties": map[string]interface{}{
					"type":   map[string]string{"type": "string"},
					"title":  map[string]string{"type": "string"},
					"status": map[string]string{"type": "integer"},
					"detail": map[string]string{"type": "string"},
				},
			},
			"AgentFingerprint": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"system_prompt_hash": map[string]string{"type": "string"},
					"tool_fingerprint":   map[string]string{"type": "string"},
					"tools":              map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}},
					"model":              map[string]string{"type": "string"},
				},
			},
			"Agent": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id":          map[string]string{"type": "string", "example": "agent://550e8400-e29b-41d4-a716-446655440000"},
					"name":        map[string]string{"type": "string"},
					"description": map[string]string{"type": "string"},
					"version":     map[string]string{"type": "string"},
					"public_key":  map[string]string{"type": "string", "description": "Base64url-encoded Ed25519 public key"},
					"key_id":      map[string]string{"type": "string", "description": "SHA-256 fingerprint of the public key"},
					"fingerprint": map[string]string{"$ref": "#/components/schemas/AgentFingerprint"},
					"parent_id":   map[string]string{"type": "string"},
					"status":      map[string]interface{}{"type": "string", "enum": []string{"active", "suspended", "revoked"}},
					"metadata":    map[string]interface{}{"type": "object", "additionalProperties": map[string]string{"type": "string"}},
					"created_at":  map[string]string{"type": "string", "format": "date-time"},
					"updated_at":  map[string]string{"type": "string", "format": "date-time"},
				},
			},
			"RegisterAgentRequest": map[string]interface{}{
				"type":     "object",
				"required": []string{"name"},
				"properties": map[string]interface{}{
					"name":          map[string]string{"type": "string"},
					"description":   map[string]string{"type": "string"},
					"version":       map[string]string{"type": "string"},
					"system_prompt": map[string]string{"type": "string"},
					"tools":         map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}},
					"model":         map[string]string{"type": "string"},
					"parent_id":     map[string]string{"type": "string"},
					"metadata":      map[string]interface{}{"type": "object", "additionalProperties": map[string]string{"type": "string"}},
				},
			},
			"BlockConditions": map[string]interface{}{
				"type":     "object",
				"required": []string{"exp"},
				"properties": map[string]interface{}{
					"exp":       map[string]interface{}{"type": "integer", "description": "Unix timestamp — token expires at"},
					"nbf":       map[string]interface{}{"type": "integer", "description": "Unix timestamp — token not valid before"},
					"max_deleg": map[string]interface{}{"type": "integer", "description": "Maximum delegation depth from this block"},
					"models":    map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}, "description": "Allowed agent models"},
				},
			},
			"IssueTokenRequest": map[string]interface{}{
				"type":     "object",
				"required": []string{"agent_id", "capabilities", "conditions"},
				"properties": map[string]interface{}{
					"agent_id":     map[string]string{"type": "string"},
					"capabilities": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}},
					"conditions":   map[string]string{"$ref": "#/components/schemas/BlockConditions"},
				},
			},
			"VerifiedACT": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"token_id":        map[string]string{"type": "string"},
					"agent_id":        map[string]string{"type": "string"},
					"capabilities":    map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}},
					"expires_at":      map[string]interface{}{"type": "integer"},
					"chain_depth":     map[string]interface{}{"type": "integer"},
					"delegation_path": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}},
				},
			},
			"Policy": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id":         map[string]string{"type": "string"},
					"name":       map[string]string{"type": "string"},
					"expression": map[string]string{"type": "string", "description": "CEL expression evaluating to bool"},
					"action":     map[string]interface{}{"type": "string", "enum": []string{"allow", "deny"}},
					"priority":   map[string]interface{}{"type": "integer"},
					"created_at": map[string]string{"type": "string", "format": "date-time"},
				},
			},
			"CreatePolicyRequest": map[string]interface{}{
				"type":     "object",
				"required": []string{"name", "expression", "action"},
				"properties": map[string]interface{}{
					"name":       map[string]string{"type": "string"},
					"expression": map[string]string{"type": "string"},
					"action":     map[string]interface{}{"type": "string", "enum": []string{"allow", "deny"}},
					"priority":   map[string]interface{}{"type": "integer", "default": 0},
				},
			},
		},
	},
	"paths": map[string]interface{}{
		"/health": map[string]interface{}{
			"get": map[string]interface{}{
				"summary":     "Liveness check",
				"operationId": "healthCheck",
				"security":    []interface{}{},
				"tags":        []string{"Health"},
				"responses": map[string]interface{}{
					"200": map[string]interface{}{"description": "Service is running"},
				},
			},
		},
		"/ready": map[string]interface{}{
			"get": map[string]interface{}{
				"summary":     "Readiness check",
				"operationId": "readinessCheck",
				"security":    []interface{}{},
				"tags":        []string{"Health"},
				"responses": map[string]interface{}{
					"200": map[string]interface{}{"description": "Service is ready"},
					"503": map[string]interface{}{"description": "Service unavailable"},
				},
			},
		},
		"/metrics": map[string]interface{}{
			"get": map[string]interface{}{
				"summary":     "Prometheus metrics",
				"operationId": "getMetrics",
				"security":    []interface{}{},
				"tags":        []string{"Observability"},
				"responses": map[string]interface{}{
					"200": map[string]interface{}{"description": "Prometheus text format metrics"},
				},
			},
		},
		"/api/v1/agents": map[string]interface{}{
			"post": map[string]interface{}{
				"summary":     "Register agent",
				"operationId": "registerAgent",
				"tags":        []string{"Agents"},
				"requestBody": map[string]interface{}{
					"required": true,
					"content":  map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]string{"$ref": "#/components/schemas/RegisterAgentRequest"}}},
				},
				"responses": map[string]interface{}{
					"201": map[string]interface{}{
						"description": "Agent registered",
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"agent":       map[string]string{"$ref": "#/components/schemas/Agent"},
										"private_key": map[string]string{"type": "string", "description": "Base64url-encoded Ed25519 private key — store securely, returned only once"},
									},
								},
							},
						},
					},
					"400": map[string]interface{}{"description": "Invalid request", "content": map[string]interface{}{"application/problem+json": map[string]interface{}{"schema": map[string]string{"$ref": "#/components/schemas/Problem"}}}},
				},
			},
			"get": map[string]interface{}{
				"summary":     "List agents",
				"operationId": "listAgents",
				"tags":        []string{"Agents"},
				"parameters": []map[string]interface{}{
					{"name": "status", "in": "query", "schema": map[string]string{"type": "string"}},
					{"name": "parent_id", "in": "query", "schema": map[string]string{"type": "string"}},
					{"name": "model", "in": "query", "schema": map[string]string{"type": "string"}},
					{"name": "limit", "in": "query", "schema": map[string]interface{}{"type": "integer", "default": 50}},
					{"name": "offset", "in": "query", "schema": map[string]interface{}{"type": "integer", "default": 0}},
				},
				"responses": map[string]interface{}{
					"200": map[string]interface{}{
						"description": "Agent list",
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{"type": "array", "items": map[string]string{"$ref": "#/components/schemas/Agent"}},
							},
						},
					},
				},
			},
		},
		"/api/v1/agents/{id}": map[string]interface{}{
			"get": map[string]interface{}{
				"summary":     "Get agent",
				"operationId": "getAgent",
				"tags":        []string{"Agents"},
				"parameters":  []map[string]interface{}{{"name": "id", "in": "path", "required": true, "schema": map[string]string{"type": "string"}}},
				"responses": map[string]interface{}{
					"200": map[string]interface{}{"description": "Agent", "content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]string{"$ref": "#/components/schemas/Agent"}}}},
					"404": map[string]interface{}{"description": "Not found"},
				},
			},
		},
		"/api/v1/agents/{id}/suspend": map[string]interface{}{
			"post": map[string]interface{}{
				"summary":     "Suspend agent",
				"operationId": "suspendAgent",
				"tags":        []string{"Agents"},
				"parameters":  []map[string]interface{}{{"name": "id", "in": "path", "required": true, "schema": map[string]string{"type": "string"}}},
				"responses":   map[string]interface{}{"200": map[string]interface{}{"description": "Agent suspended"}, "409": map[string]interface{}{"description": "Agent already revoked"}},
			},
		},
		"/api/v1/agents/{id}/revoke": map[string]interface{}{
			"post": map[string]interface{}{
				"summary":     "Revoke agent",
				"operationId": "revokeAgent",
				"tags":        []string{"Agents"},
				"parameters":  []map[string]interface{}{{"name": "id", "in": "path", "required": true, "schema": map[string]string{"type": "string"}}},
				"requestBody": map[string]interface{}{
					"content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"cascade": map[string]string{"type": "boolean"}}}}},
				},
				"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Agent revoked"}},
			},
		},
		"/api/v1/agents/{id}/rotate-key": map[string]interface{}{
			"post": map[string]interface{}{
				"summary":     "Rotate agent key",
				"operationId": "rotateAgentKey",
				"tags":        []string{"Agents"},
				"parameters":  []map[string]interface{}{{"name": "id", "in": "path", "required": true, "schema": map[string]string{"type": "string"}}},
				"responses": map[string]interface{}{
					"200": map[string]interface{}{
						"description": "New key pair generated",
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"agent":       map[string]string{"$ref": "#/components/schemas/Agent"},
										"private_key": map[string]string{"type": "string"},
									},
								},
							},
						},
					},
				},
			},
		},
		"/api/v1/agents/{id}/tree": map[string]interface{}{
			"get": map[string]interface{}{
				"summary":     "Get delegation tree",
				"operationId": "getDelegationTree",
				"tags":        []string{"Agents"},
				"parameters":  []map[string]interface{}{{"name": "id", "in": "path", "required": true, "schema": map[string]string{"type": "string"}}},
				"responses":   map[string]interface{}{"200": map[string]interface{}{"description": "Delegation tree"}},
			},
		},
		"/api/v1/tokens/issue": map[string]interface{}{
			"post": map[string]interface{}{
				"summary":     "Issue root ACT token",
				"operationId": "issueToken",
				"tags":        []string{"Tokens"},
				"requestBody": map[string]interface{}{
					"required": true,
					"content":  map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]string{"$ref": "#/components/schemas/IssueTokenRequest"}}},
				},
				"responses": map[string]interface{}{
					"201": map[string]interface{}{
						"description": "Token issued",
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"token":    map[string]string{"type": "string", "description": "Base64url-encoded ACT"},
										"token_id": map[string]string{"type": "string"},
									},
								},
							},
						},
					},
					"400": map[string]interface{}{"description": "Invalid request or capabilities"},
					"403": map[string]interface{}{"description": "Agent not active or policy denied"},
					"404": map[string]interface{}{"description": "Agent not found"},
				},
			},
		},
		"/api/v1/tokens/delegate": map[string]interface{}{
			"post": map[string]interface{}{
				"summary":     "Submit pre-signed delegated token",
				"operationId": "submitDelegatedToken",
				"description": "Accepts a client-side-signed delegated ACT. The server verifies all signatures and records the audit event. Agent private keys are never sent to the server.",
				"tags":        []string{"Tokens"},
				"requestBody": map[string]interface{}{
					"required": true,
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{
								"type":     "object",
								"required": []string{"delegated_token"},
								"properties": map[string]interface{}{
									"delegated_token": map[string]string{"type": "string", "description": "Base64url-encoded delegated ACT, pre-signed by the parent agent"},
								},
							},
						},
					},
				},
				"responses": map[string]interface{}{
					"201": map[string]interface{}{"description": "Token verified and recorded"},
					"400": map[string]interface{}{"description": "Invalid or tampered token"},
				},
			},
		},
		"/api/v1/tokens/verify": map[string]interface{}{
			"post": map[string]interface{}{
				"summary":     "Verify ACT token",
				"operationId": "verifyToken",
				"tags":        []string{"Tokens"},
				"requestBody": map[string]interface{}{
					"required": true,
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{
								"type":       "object",
								"properties": map[string]interface{}{"token": map[string]string{"type": "string"}},
							},
						},
					},
				},
				"responses": map[string]interface{}{
					"200": map[string]interface{}{"description": "Token valid", "content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]string{"$ref": "#/components/schemas/VerifiedACT"}}}},
					"401": map[string]interface{}{"description": "Invalid or expired token"},
					"403": map[string]interface{}{"description": "Policy denied"},
				},
			},
		},
		"/api/v1/tokens/revoke": map[string]interface{}{
			"post": map[string]interface{}{
				"summary":     "Revoke token",
				"operationId": "revokeToken",
				"tags":        []string{"Tokens"},
				"requestBody": map[string]interface{}{
					"required": true,
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"token_id": map[string]string{"type": "string"},
									"reason":   map[string]string{"type": "string"},
								},
							},
						},
					},
				},
				"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Token revoked"}},
			},
		},
		"/api/v1/admin/policies": map[string]interface{}{
			"get": map[string]interface{}{
				"summary":     "List policies",
				"operationId": "listPolicies",
				"tags":        []string{"Admin"},
				"responses": map[string]interface{}{
					"200": map[string]interface{}{
						"description": "Policy list",
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{"type": "array", "items": map[string]string{"$ref": "#/components/schemas/Policy"}},
							},
						},
					},
				},
			},
			"post": map[string]interface{}{
				"summary":     "Create policy",
				"operationId": "createPolicy",
				"tags":        []string{"Admin"},
				"requestBody": map[string]interface{}{
					"required": true,
					"content":  map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]string{"$ref": "#/components/schemas/CreatePolicyRequest"}}},
				},
				"responses": map[string]interface{}{
					"201": map[string]interface{}{"description": "Policy created", "content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]string{"$ref": "#/components/schemas/Policy"}}}},
					"400": map[string]interface{}{"description": "Invalid CEL expression or action"},
				},
			},
		},
		"/api/v1/admin/policies/{id}": map[string]interface{}{
			"delete": map[string]interface{}{
				"summary":     "Delete policy",
				"operationId": "deletePolicy",
				"tags":        []string{"Admin"},
				"parameters":  []map[string]interface{}{{"name": "id", "in": "path", "required": true, "schema": map[string]string{"type": "string"}}},
				"responses":   map[string]interface{}{"200": map[string]interface{}{"description": "Policy deleted"}, "404": map[string]interface{}{"description": "Not found"}},
			},
		},
		"/api/v1/admin/stats": map[string]interface{}{
			"get": map[string]interface{}{
				"summary":     "Server statistics",
				"operationId": "getStats",
				"tags":        []string{"Admin"},
				"responses":   map[string]interface{}{"200": map[string]interface{}{"description": "Stats"}},
			},
		},
		"/api/v1/audit": map[string]interface{}{
			"get": map[string]interface{}{
				"summary":     "List audit entries",
				"operationId": "listAuditEntries",
				"tags":        []string{"Audit"},
				"parameters": []map[string]interface{}{
					{"name": "limit", "in": "query", "schema": map[string]interface{}{"type": "integer", "default": 50}},
					{"name": "offset", "in": "query", "schema": map[string]interface{}{"type": "integer", "default": 0}},
				},
				"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Audit log entries"}},
			},
		},
		"/.well-known/openid-configuration": map[string]interface{}{
			"get": map[string]interface{}{
				"summary":     "OIDC discovery document",
				"operationId": "oidcDiscovery",
				"security":    []interface{}{},
				"tags":        []string{"OIDC"},
				"responses":   map[string]interface{}{"200": map[string]interface{}{"description": "OIDC configuration"}},
			},
		},
		"/.well-known/jwks.json": map[string]interface{}{
			"get": map[string]interface{}{
				"summary":     "JSON Web Key Set",
				"operationId": "jwks",
				"security":    []interface{}{},
				"tags":        []string{"OIDC"},
				"responses":   map[string]interface{}{"200": map[string]interface{}{"description": "JWKS"}},
			},
		},
		"/oauth/token": map[string]interface{}{
			"post": map[string]interface{}{
				"summary":     "OAuth2.1 token exchange (ACT → JWT)",
				"operationId": "oauthToken",
				"security":    []interface{}{},
				"tags":        []string{"OAuth"},
				"responses":   map[string]interface{}{"200": map[string]interface{}{"description": "JWT access token"}},
			},
		},
		"/oauth/introspect": map[string]interface{}{
			"post": map[string]interface{}{
				"summary":     "Token introspection (RFC 7662)",
				"operationId": "oauthIntrospect",
				"security":    []interface{}{},
				"tags":        []string{"OAuth"},
				"responses":   map[string]interface{}{"200": map[string]interface{}{"description": "Introspection response"}},
			},
		},
		"/oauth/revoke": map[string]interface{}{
			"post": map[string]interface{}{
				"summary":     "Token revocation (RFC 7009)",
				"operationId": "oauthRevoke",
				"security":    []interface{}{},
				"tags":        []string{"OAuth"},
				"responses":   map[string]interface{}{"200": map[string]interface{}{"description": "Token revoked"}},
			},
		},
	},
}

// OpenAPISpec handles GET /api/v1/openapi.json — no auth required.
func OpenAPISpec(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(openAPISpec)
}

// SwaggerUI handles GET /docs — redirects to Swagger UI CDN pre-loaded with our spec.
func SwaggerUI(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	specURL := scheme + "://" + r.Host + "/api/v1/openapi.json"
	swaggerURL := "https://petstore.swagger.io/?url=" + specURL
	http.Redirect(w, r, swaggerURL, http.StatusFound)
}
