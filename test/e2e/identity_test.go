package e2e_test

import (
	"net/http"
	"testing"
)

func TestAgentRegistration(t *testing.T) {
	ts := newTestServer(t)

	t.Run("register agent succeeds", func(t *testing.T) {
		agent, privKey := registerAgent(t, ts, "alpha")
		if agent["id"] == nil || agent["id"] == "" {
			t.Fatal("expected non-empty agent id")
		}
		if privKey == "" {
			t.Fatal("expected private_key in response")
		}
		if agent["status"] != "active" {
			t.Fatalf("expected status=active, got %v", agent["status"])
		}
		if agent["public_key"] == nil || agent["public_key"] == "" {
			t.Fatal("expected public_key in agent")
		}
	})

	t.Run("register without name returns 400", func(t *testing.T) {
		resp := ts.do(t, http.MethodPost, "/api/v1/agents", map[string]interface{}{
			"description": "no name here",
		})
		mustStatus(t, resp, http.StatusBadRequest)
		resp.Body.Close()
	})

	t.Run("registration requires admin key", func(t *testing.T) {
		resp := ts.doNoAuth(t, http.MethodPost, "/api/v1/agents", map[string]interface{}{
			"name": "unauthorized-agent",
		})
		mustStatus(t, resp, http.StatusUnauthorized)
		resp.Body.Close()
	})

	t.Run("wrong admin key returns 403", func(t *testing.T) {
		resp := ts.doWithKey(t, http.MethodPost, "/api/v1/agents", map[string]interface{}{
			"name": "bad-key-agent",
		}, "wrong-key")
		mustStatus(t, resp, http.StatusForbidden)
		resp.Body.Close()
	})
}

func TestAgentGet(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "beta")
	agentID := agent["id"].(string)

	t.Run("get existing agent", func(t *testing.T) {
		resp := ts.do(t, http.MethodGet, "/api/v1/agents/"+agentUUID(agentID), nil)
		mustStatus(t, resp, http.StatusOK)
		var got map[string]interface{}
		decodeJSON(t, resp, &got)
		if got["id"] != agentID {
			t.Fatalf("expected id=%s, got %v", agentID, got["id"])
		}
	})

	t.Run("get unknown agent returns 404", func(t *testing.T) {
		resp := ts.do(t, http.MethodGet, "/api/v1/agents/00000000-0000-0000-0000-000000000000", nil)
		mustStatus(t, resp, http.StatusNotFound)
		resp.Body.Close()
	})
}

func TestAgentList(t *testing.T) {
	ts := newTestServer(t)
	registerAgent(t, ts, "list-agent-1")
	registerAgent(t, ts, "list-agent-2")
	registerAgent(t, ts, "list-agent-3")

	t.Run("list returns all registered agents", func(t *testing.T) {
		resp := ts.do(t, http.MethodGet, "/api/v1/agents", nil)
		mustStatus(t, resp, http.StatusOK)
		var result map[string]interface{}
		decodeJSON(t, resp, &result)
		agents := result["agents"].([]interface{})
		if len(agents) < 3 {
			t.Fatalf("expected at least 3 agents, got %d", len(agents))
		}
		count := result["count"].(float64)
		if int(count) != len(agents) {
			t.Fatalf("count=%d does not match agents length=%d", int(count), len(agents))
		}
	})
}

func TestAgentSuspend(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "suspendable")
	agentID := agent["id"].(string)
	uuid := agentUUID(agentID)

	t.Run("suspend active agent", func(t *testing.T) {
		resp := ts.do(t, http.MethodPost, "/api/v1/agents/"+uuid+"/suspend", nil)
		mustStatus(t, resp, http.StatusOK)
		var result map[string]interface{}
		decodeJSON(t, resp, &result)
		if result["status"] != "suspended" {
			t.Fatalf("expected status=suspended, got %v", result["status"])
		}
	})

	t.Run("get suspended agent shows correct status", func(t *testing.T) {
		resp := ts.do(t, http.MethodGet, "/api/v1/agents/"+uuid, nil)
		mustStatus(t, resp, http.StatusOK)
		var got map[string]interface{}
		decodeJSON(t, resp, &got)
		if got["status"] != "suspended" {
			t.Fatalf("expected status=suspended, got %v", got["status"])
		}
	})
}

func TestAgentRevoke(t *testing.T) {
	ts := newTestServer(t)

	t.Run("revoke active agent", func(t *testing.T) {
		agent, _ := registerAgent(t, ts, "revocable")
		uuid := agentUUID(agent["id"].(string))

		resp := ts.do(t, http.MethodPost, "/api/v1/agents/"+uuid+"/revoke", map[string]interface{}{
			"cascade": false,
		})
		mustStatus(t, resp, http.StatusOK)
		resp.Body.Close()

		// Confirm status is revoked.
		resp2 := ts.do(t, http.MethodGet, "/api/v1/agents/"+uuid, nil)
		mustStatus(t, resp2, http.StatusOK)
		var got map[string]interface{}
		decodeJSON(t, resp2, &got)
		if got["status"] != "revoked" {
			t.Fatalf("expected status=revoked, got %v", got["status"])
		}
	})

	t.Run("cascade revoke revokes children", func(t *testing.T) {
		parent, _ := registerAgent(t, ts, "parent-cascade")
		parentID := parent["id"].(string)

		// Register child with parent_id.
		resp := ts.do(t, http.MethodPost, "/api/v1/agents", map[string]interface{}{
			"name":      "child-of-parent",
			"parent_id": parentID,
		})
		mustStatus(t, resp, http.StatusCreated)
		var childResult map[string]interface{}
		decodeJSON(t, resp, &childResult)
		childAgent := childResult["agent"].(map[string]interface{})
		childUUID := agentUUID(childAgent["id"].(string))

		// Cascade revoke the parent.
		resp2 := ts.do(t, http.MethodPost, "/api/v1/agents/"+agentUUID(parentID)+"/revoke", map[string]interface{}{
			"cascade": true,
		})
		mustStatus(t, resp2, http.StatusOK)
		resp2.Body.Close()

		// Child should also be revoked.
		resp3 := ts.do(t, http.MethodGet, "/api/v1/agents/"+childUUID, nil)
		mustStatus(t, resp3, http.StatusOK)
		var childGot map[string]interface{}
		decodeJSON(t, resp3, &childGot)
		if childGot["status"] != "revoked" {
			t.Fatalf("expected child status=revoked after cascade, got %v", childGot["status"])
		}
	})
}

func TestKeyRotation(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "key-rotator")
	agentID := agent["id"].(string)
	uuid := agentUUID(agentID)
	originalKey := agent["key_id"].(string)

	resp := ts.do(t, http.MethodPost, "/api/v1/agents/"+uuid+"/rotate-key", nil)
	mustStatus(t, resp, http.StatusOK)
	var result map[string]interface{}
	decodeJSON(t, resp, &result)

	if result["private_key"] == nil || result["private_key"] == "" {
		t.Fatal("expected new private_key in rotate-key response")
	}
	newAgent := result["agent"].(map[string]interface{})
	if newAgent["key_id"] == originalKey {
		t.Fatal("expected key_id to change after rotation")
	}

	t.Run("cannot rotate key for revoked agent", func(t *testing.T) {
		agent2, _ := registerAgent(t, ts, "revoked-rotator")
		uuid2 := agentUUID(agent2["id"].(string))

		// Revoke first.
		resp := ts.do(t, http.MethodPost, "/api/v1/agents/"+uuid2+"/revoke", nil)
		mustStatus(t, resp, http.StatusOK)
		resp.Body.Close()

		// Then try to rotate.
		resp2 := ts.do(t, http.MethodPost, "/api/v1/agents/"+uuid2+"/rotate-key", nil)
		mustStatus(t, resp2, http.StatusBadRequest)
		resp2.Body.Close()
	})
}

func TestDelegationTree(t *testing.T) {
	ts := newTestServer(t)

	parent, _ := registerAgent(t, ts, "tree-parent")
	parentID := parent["id"].(string)

	// Register two children.
	resp := ts.do(t, http.MethodPost, "/api/v1/agents", map[string]interface{}{
		"name":      "tree-child-1",
		"parent_id": parentID,
	})
	mustStatus(t, resp, http.StatusCreated)
	resp.Body.Close()

	resp = ts.do(t, http.MethodPost, "/api/v1/agents", map[string]interface{}{
		"name":      "tree-child-2",
		"parent_id": parentID,
	})
	mustStatus(t, resp, http.StatusCreated)
	resp.Body.Close()

	treeResp := ts.do(t, http.MethodGet, "/api/v1/agents/"+agentUUID(parentID)+"/tree", nil)
	mustStatus(t, treeResp, http.StatusOK)
	var tree map[string]interface{}
	decodeJSON(t, treeResp, &tree)

	children := tree["children"].([]interface{})
	if len(children) != 2 {
		t.Fatalf("expected 2 children in delegation tree, got %d", len(children))
	}
}
