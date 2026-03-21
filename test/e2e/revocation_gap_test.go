package e2e_test

// TestRevocationGap_AgentRevoke_TokenStillVerifies documents a known bug:
//
// When an agent is revoked via POST /api/v1/agents/{id}/revoke, the revocation
// is written to the identity store (Postgres/memory) but NOT to the revocation
// registry (Redis/memory). Token verification checks the revocation registry,
// not the identity store — so a revoked agent's token continues to pass
// verification.
//
// These tests are written to FAIL on the current code, proving the gap exists.
// Once the fix is applied (wiring revocationReg into RevokeAgent), these tests
// should pass.
//
// Bug: handlers_identity.go → RevokeAgent calls service.RevokeAgent() which
// only updates the store. It never calls revocationReg.RevokeAgent().
// Fix: pass revocation.Registry to IdentityHandlers and call
// revocationReg.RevokeAgent() from the RevokeAgent handler.

import (
	"net/http"
	"testing"
)

// TestRevocationGap_RevokedAgentToken_ShouldBeRejectedOnVerify proves that
// after revoking an agent, its existing token should be rejected by verify.
//
// CURRENT BEHAVIOUR (bug): verify returns 200 — token passes.
// EXPECTED BEHAVIOUR (fix): verify returns 401 — token is rejected.
func TestRevocationGap_RevokedAgentToken_ShouldBeRejectedOnVerify(t *testing.T) {
	ts := newTestServer(t)

	// Step 1: Register agent and issue a token.
	agent, _ := registerAgent(t, ts, "revocation-gap-agent")
	agentID := agent["id"].(string)
	tok := issueToken(t, ts, agentID, []string{"read"}, 3600)

	// Step 2: Confirm token verifies successfully before revocation.
	preResp := ts.do(t, http.MethodPost, "/api/v1/tokens/verify", map[string]interface{}{
		"token": tok,
	})
	mustStatus(t, preResp, http.StatusOK)
	preResp.Body.Close()

	// Step 3: Revoke the agent via the identity endpoint.
	revokeResp := ts.do(t, http.MethodPost, "/api/v1/agents/"+agentUUID(agentID)+"/revoke", map[string]interface{}{
		"cascade": false,
	})
	mustStatus(t, revokeResp, http.StatusOK)
	revokeResp.Body.Close()

	// Step 4: Confirm the agent's status is "revoked" in the store.
	getResp := ts.do(t, http.MethodGet, "/api/v1/agents/"+agentUUID(agentID), nil)
	mustStatus(t, getResp, http.StatusOK)
	var agentData map[string]interface{}
	decodeJSON(t, getResp, &agentData)
	if agentData["status"] != "revoked" {
		t.Fatalf("precondition: expected agent status=revoked in store, got %v", agentData["status"])
	}

	// Step 5: Now try to verify the previously-issued token.
	// EXPECTED: 401 — the agent is revoked, the token should be rejected.
	// ACTUAL (bug): 200 — the token passes because the revocation registry was
	// never written to when the agent was revoked.
	postResp := ts.do(t, http.MethodPost, "/api/v1/tokens/verify", map[string]interface{}{
		"token": tok,
	})
	defer postResp.Body.Close()

	if postResp.StatusCode == http.StatusOK {
		t.Fatal(
			"BUG CONFIRMED: token of a revoked agent still verifies successfully (got 200). " +
				"Agent revocation via POST /api/v1/agents/{id}/revoke does not write to the " +
				"revocation registry, so token verification cannot detect the revocation. " +
				"Fix: wire revocation.Registry into IdentityHandlers and call " +
				"revocationReg.RevokeAgent() from the RevokeAgent handler.",
		)
	}

	mustStatus(t, postResp, http.StatusUnauthorized)
}

// TestRevocationGap_CascadeRevoke_ChildTokenStillVerifies proves that after
// cascade-revoking a parent agent, child agents' tokens should also be rejected.
//
// CURRENT BEHAVIOUR (bug): child token verify returns 200 — passes.
// EXPECTED BEHAVIOUR (fix): child token verify returns 401 — rejected.
func TestRevocationGap_CascadeRevoke_ChildTokenStillVerifies(t *testing.T) {
	ts := newTestServer(t)

	// Step 1: Register parent and child agents.
	parent, _ := registerAgent(t, ts, "cascade-gap-parent")
	parentID := parent["id"].(string)

	childResp := ts.do(t, http.MethodPost, "/api/v1/agents", map[string]interface{}{
		"name":      "cascade-gap-child",
		"parent_id": parentID,
	})
	mustStatus(t, childResp, http.StatusCreated)
	var childResult map[string]interface{}
	decodeJSON(t, childResp, &childResult)
	childAgent := childResult["agent"].(map[string]interface{})
	childID := childAgent["id"].(string)

	// Step 2: Issue a token to the child agent.
	childTok := issueToken(t, ts, childID, []string{"read"}, 3600)

	// Step 3: Confirm child token verifies before cascade revocation.
	preResp := ts.do(t, http.MethodPost, "/api/v1/tokens/verify", map[string]interface{}{
		"token": childTok,
	})
	mustStatus(t, preResp, http.StatusOK)
	preResp.Body.Close()

	// Step 4: Cascade-revoke the parent — child should also be revoked.
	revokeResp := ts.do(t, http.MethodPost, "/api/v1/agents/"+agentUUID(parentID)+"/revoke", map[string]interface{}{
		"cascade": true,
	})
	mustStatus(t, revokeResp, http.StatusOK)
	revokeResp.Body.Close()

	// Step 5: Confirm child agent's status is "revoked" in the store.
	getResp := ts.do(t, http.MethodGet, "/api/v1/agents/"+agentUUID(childID), nil)
	mustStatus(t, getResp, http.StatusOK)
	var childData map[string]interface{}
	decodeJSON(t, getResp, &childData)
	if childData["status"] != "revoked" {
		t.Fatalf("precondition: expected child status=revoked in store, got %v", childData["status"])
	}

	// Step 6: Verify the child's token — should be 401.
	// ACTUAL (bug): 200 — cascade revocation writes to the store but not to
	// the revocation registry, so verify cannot detect revoked children.
	postResp := ts.do(t, http.MethodPost, "/api/v1/tokens/verify", map[string]interface{}{
		"token": childTok,
	})
	defer postResp.Body.Close()

	if postResp.StatusCode == http.StatusOK {
		t.Fatal(
			"BUG CONFIRMED: child agent token still verifies after cascade revocation of parent (got 200). " +
				"revokeChildren() in identity/service.go only updates the store, never the revocation registry. " +
				"Fix: call revocationReg.RevokeAgent() for each child agent during cascade revocation.",
		)
	}

	mustStatus(t, postResp, http.StatusUnauthorized)
}

// TestRevocationGap_TokenRevoke_WorksCorrectly confirms that the TOKEN revocation
// path (POST /api/v1/tokens/revoke) DOES work correctly, unlike agent revocation.
// This is a control test — it should pass today and continue passing after the fix.
func TestRevocationGap_TokenRevoke_WorksCorrectly(t *testing.T) {
	ts := newTestServer(t)

	// Register agent and issue token.
	agent, _ := registerAgent(t, ts, "token-revoke-control")
	agentID := agent["id"].(string)
	tok := issueToken(t, ts, agentID, []string{"read"}, 3600)

	// Decode token to get token_id.
	var tokenData map[string]interface{}
	issueResp := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
		"agent_id":     agentID,
		"capabilities": []string{"read"},
		"conditions":   map[string]interface{}{"exp": futureExpiry(3600)},
	})
	mustStatus(t, issueResp, http.StatusCreated)
	decodeJSON(t, issueResp, &tokenData)
	tokenID := tokenData["token_id"].(string)
	tok2 := tokenData["token"].(string)

	// Confirm token verifies.
	preResp := ts.do(t, http.MethodPost, "/api/v1/tokens/verify", map[string]interface{}{
		"token": tok2,
	})
	mustStatus(t, preResp, http.StatusOK)
	preResp.Body.Close()
	_ = tok // suppress unused warning

	// Revoke the token directly via /tokens/revoke.
	revokeResp := ts.do(t, http.MethodPost, "/api/v1/tokens/revoke", map[string]interface{}{
		"token_id": tokenID,
		"reason":   "control test",
	})
	mustStatus(t, revokeResp, http.StatusOK)
	revokeResp.Body.Close()

	// Verify should now return 401 — this path IS correctly implemented.
	postResp := ts.do(t, http.MethodPost, "/api/v1/tokens/verify", map[string]interface{}{
		"token": tok2,
	})
	mustStatus(t, postResp, http.StatusUnauthorized)
	postResp.Body.Close()
}

// TestRevocationGap_IssueAfterAgentRevoke_ShouldBeBlocked confirms that issuing
// a NEW token for a revoked agent is correctly blocked (because IssueToken checks
// agent.Status from the store before issuing).
// This path works today — the gap only affects EXISTING tokens.
func TestRevocationGap_IssueAfterAgentRevoke_ShouldBeBlocked(t *testing.T) {
	ts := newTestServer(t)

	agent, _ := registerAgent(t, ts, "issue-after-revoke")
	agentID := agent["id"].(string)

	// Revoke the agent.
	revokeResp := ts.do(t, http.MethodPost, "/api/v1/agents/"+agentUUID(agentID)+"/revoke", nil)
	mustStatus(t, revokeResp, http.StatusOK)
	revokeResp.Body.Close()

	// Trying to issue a NEW token for a revoked agent should be 403.
	// This works correctly today because IssueToken checks agent.Status from the store.
	issueResp := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
		"agent_id":     agentID,
		"capabilities": []string{"read"},
		"conditions":   map[string]interface{}{"exp": futureExpiry(3600)},
	})
	mustStatus(t, issueResp, http.StatusForbidden)
	issueResp.Body.Close()
}
