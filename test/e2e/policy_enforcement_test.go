package e2e_test

import (
	"net/http"
	"testing"
)

func TestPolicyEnforcement_NoPolicies_DefaultAllow(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "policy-agent-default")
	agentID := agent["id"].(string)

	// With no policies configured, issue and verify should succeed.
	tok := issueToken(t, ts, agentID, []string{"read"}, 3600)
	if tok == "" {
		t.Fatal("expected non-empty token with no policies")
	}

	resp := ts.do(t, http.MethodPost, "/api/v1/tokens/verify", map[string]interface{}{
		"token": tok,
	})
	mustStatus(t, resp, http.StatusOK)
	resp.Body.Close()
}

func TestPolicyEnforcement_DenyPolicy_BlocksIssuance(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "policy-deny-agent")
	agentID := agent["id"].(string)

	// Create a deny-all policy.
	createResp := ts.do(t, http.MethodPost, "/api/v1/admin/policies", map[string]interface{}{
		"name":       "deny-all",
		"expression": `true`,
		"action":     "deny",
		"priority":   100,
	})
	mustStatus(t, createResp, http.StatusCreated)
	createResp.Body.Close()

	// Issue should now be denied by policy.
	resp := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
		"agent_id":     agentID,
		"capabilities": []string{"read"},
		"conditions":   map[string]interface{}{"exp": futureExpiry(3600)},
	})
	mustStatus(t, resp, http.StatusForbidden)
	var body map[string]interface{}
	decodeJSON(t, resp, &body)
	if body["type"] != "https://agentity.dev/errors/policy-denied" {
		t.Fatalf("expected policy-denied error type, got %v", body["type"])
	}
}

func TestPolicyEnforcement_AllowPolicy_RequiresCapabilityMatch(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "policy-allow-agent")
	agentID := agent["id"].(string)

	// Allow only if token includes "read" capability.
	createResp := ts.do(t, http.MethodPost, "/api/v1/admin/policies", map[string]interface{}{
		"name":       "require-read",
		"expression": `"read" in capabilities`,
		"action":     "allow",
		"priority":   10,
	})
	mustStatus(t, createResp, http.StatusCreated)
	createResp.Body.Close()

	// Issue with "read" — should succeed.
	resp := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
		"agent_id":     agentID,
		"capabilities": []string{"read"},
		"conditions":   map[string]interface{}{"exp": futureExpiry(3600)},
	})
	mustStatus(t, resp, http.StatusCreated)
	resp.Body.Close()

	// Issue with only "write" — allow policy doesn't match → denied.
	resp2 := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
		"agent_id":     agentID,
		"capabilities": []string{"write"},
		"conditions":   map[string]interface{}{"exp": futureExpiry(3600)},
	})
	mustStatus(t, resp2, http.StatusForbidden)
	resp2.Body.Close()
}

func TestPolicyEnforcement_DenyPolicy_BlocksVerification(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "policy-verify-deny")
	agentID := agent["id"].(string)

	// Issue a token before adding the deny policy.
	tok := issueToken(t, ts, agentID, []string{"read"}, 3600)

	// Now add a deny-all policy.
	createResp := ts.do(t, http.MethodPost, "/api/v1/admin/policies", map[string]interface{}{
		"name":       "deny-verification",
		"expression": `true`,
		"action":     "deny",
		"priority":   200,
	})
	mustStatus(t, createResp, http.StatusCreated)
	createResp.Body.Close()

	// Verification should now be denied by policy.
	resp := ts.do(t, http.MethodPost, "/api/v1/tokens/verify", map[string]interface{}{
		"token": tok,
	})
	mustStatus(t, resp, http.StatusForbidden)
	var body map[string]interface{}
	decodeJSON(t, resp, &body)
	if body["type"] != "https://agentity.dev/errors/policy-denied" {
		t.Fatalf("expected policy-denied error type, got %v", body["type"])
	}
}

func TestPolicyEnforcement_DeletePolicy_RestoresAccess(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "policy-delete-restore")
	agentID := agent["id"].(string)

	// Add deny policy.
	createResp := ts.do(t, http.MethodPost, "/api/v1/admin/policies", map[string]interface{}{
		"name":       "temp-deny",
		"expression": `true`,
		"action":     "deny",
		"priority":   50,
	})
	mustStatus(t, createResp, http.StatusCreated)
	var created map[string]interface{}
	decodeJSON(t, createResp, &created)
	policyID := created["id"].(string)

	// Issue is denied.
	denyResp := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
		"agent_id":     agentID,
		"capabilities": []string{"read"},
		"conditions":   map[string]interface{}{"exp": futureExpiry(3600)},
	})
	mustStatus(t, denyResp, http.StatusForbidden)
	denyResp.Body.Close()

	// Delete the policy.
	deleteResp := ts.do(t, http.MethodDelete, "/api/v1/admin/policies/"+policyID, nil)
	mustStatus(t, deleteResp, http.StatusOK)
	deleteResp.Body.Close()

	// Issue should succeed now.
	allowResp := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
		"agent_id":     agentID,
		"capabilities": []string{"read"},
		"conditions":   map[string]interface{}{"exp": futureExpiry(3600)},
	})
	mustStatus(t, allowResp, http.StatusCreated)
	allowResp.Body.Close()
}

func TestPolicyEnforcement_ChainDepthDenyPolicy(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "policy-chain-depth")
	agentID := agent["id"].(string)

	// Issue a root token (chain_depth=0 at issue time, depth evaluated at verify).
	tok := issueToken(t, ts, agentID, []string{"read"}, 3600)

	// Add deny policy: deny chain_depth > 1.
	createResp := ts.do(t, http.MethodPost, "/api/v1/admin/policies", map[string]interface{}{
		"name":       "no-deep-chain",
		"expression": `chain_depth > 1`,
		"action":     "deny",
		"priority":   100,
	})
	mustStatus(t, createResp, http.StatusCreated)
	createResp.Body.Close()

	// A root token (chain_depth=1) should still verify.
	resp := ts.do(t, http.MethodPost, "/api/v1/tokens/verify", map[string]interface{}{
		"token": tok,
	})
	mustStatus(t, resp, http.StatusOK)
	resp.Body.Close()
}
