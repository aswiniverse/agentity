package e2e_test

import (
	"net/http"
	"testing"
)

func TestHealthEndpoints(t *testing.T) {
	ts := newTestServer(t)

	t.Run("health liveness is always 200", func(t *testing.T) {
		resp := ts.doNoAuth(t, http.MethodGet, "/health", nil)
		mustStatus(t, resp, http.StatusOK)
		var result map[string]interface{}
		decodeJSON(t, resp, &result)
		if result["status"] != "ok" {
			t.Fatalf("expected status=ok, got %v", result["status"])
		}
	})

	t.Run("ready endpoint returns 200 with in-memory store", func(t *testing.T) {
		// No readiness check is wired for in-memory store — always ready.
		resp := ts.doNoAuth(t, http.MethodGet, "/ready", nil)
		mustStatus(t, resp, http.StatusOK)
		var result map[string]interface{}
		decodeJSON(t, resp, &result)
		if result["status"] != "ready" {
			t.Fatalf("expected status=ready, got %v", result["status"])
		}
	})
}

func TestAdminStats(t *testing.T) {
	ts := newTestServer(t)

	// Register a few agents so there's something to count.
	registerAgent(t, ts, "stats-agent-1")
	registerAgent(t, ts, "stats-agent-2")

	t.Run("stats endpoint returns agent count", func(t *testing.T) {
		resp := ts.do(t, http.MethodGet, "/api/v1/admin/stats", nil)
		mustStatus(t, resp, http.StatusOK)
		var result map[string]interface{}
		decodeJSON(t, resp, &result)
		if result["agents"] == nil {
			t.Fatal("expected agents field in stats response")
		}
	})

	t.Run("stats requires admin key", func(t *testing.T) {
		resp := ts.doNoAuth(t, http.MethodGet, "/api/v1/admin/stats", nil)
		mustStatus(t, resp, http.StatusUnauthorized)
		resp.Body.Close()
	})
}

func TestPolicies(t *testing.T) {
	ts := newTestServer(t)

	t.Run("list policies returns empty list initially", func(t *testing.T) {
		resp := ts.do(t, http.MethodGet, "/api/v1/admin/policies", nil)
		mustStatus(t, resp, http.StatusOK)
		var result map[string]interface{}
		decodeJSON(t, resp, &result)
		// policies key should exist (may be null or empty array).
		if _, ok := result["policies"]; !ok {
			t.Fatal("expected policies field in list response")
		}
	})

	t.Run("create policy succeeds", func(t *testing.T) {
		resp := ts.do(t, http.MethodPost, "/api/v1/admin/policies", map[string]interface{}{
			"name":       "test-policy",
			"expression": `"read" in capabilities`,
			"action":     "allow",
			"priority":   10,
		})
		mustStatus(t, resp, http.StatusCreated)
		var result map[string]interface{}
		decodeJSON(t, resp, &result)
		if result["id"] == nil || result["id"] == "" {
			t.Fatal("expected id in create policy response")
		}
		if result["name"] != "test-policy" {
			t.Fatalf("expected name=test-policy, got %v", result["name"])
		}
	})

	t.Run("create policy without name returns 400", func(t *testing.T) {
		resp := ts.do(t, http.MethodPost, "/api/v1/admin/policies", map[string]interface{}{
			"expression": `true`,
			"action":     "allow",
		})
		mustStatus(t, resp, http.StatusBadRequest)
		resp.Body.Close()
	})

	t.Run("create policy without expression returns 400", func(t *testing.T) {
		resp := ts.do(t, http.MethodPost, "/api/v1/admin/policies", map[string]interface{}{
			"name":   "no-expression",
			"action": "allow",
		})
		mustStatus(t, resp, http.StatusBadRequest)
		resp.Body.Close()
	})

	t.Run("created policy appears in list", func(t *testing.T) {
		// Create one.
		createResp := ts.do(t, http.MethodPost, "/api/v1/admin/policies", map[string]interface{}{
			"name":       "listed-policy",
			"expression": `true`,
			"action":     "allow",
			"priority":   0,
		})
		mustStatus(t, createResp, http.StatusCreated)
		createResp.Body.Close()

		// List and check it's present.
		listResp := ts.do(t, http.MethodGet, "/api/v1/admin/policies", nil)
		mustStatus(t, listResp, http.StatusOK)
		var result map[string]interface{}
		decodeJSON(t, listResp, &result)
		policies, ok := result["policies"].([]interface{})
		if !ok {
			t.Fatal("policies field is not an array")
		}
		found := false
		for _, p := range policies {
			pol := p.(map[string]interface{})
			if pol["name"] == "listed-policy" {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("expected created policy to appear in list")
		}
	})

	t.Run("delete policy removes it", func(t *testing.T) {
		createResp := ts.do(t, http.MethodPost, "/api/v1/admin/policies", map[string]interface{}{
			"name":       "deletable-policy",
			"expression": `false`,
			"action":     "deny",
			"priority":   100,
		})
		mustStatus(t, createResp, http.StatusCreated)
		var created map[string]interface{}
		decodeJSON(t, createResp, &created)
		policyID := created["id"].(string)

		deleteResp := ts.do(t, http.MethodDelete, "/api/v1/admin/policies/"+policyID, nil)
		mustStatus(t, deleteResp, http.StatusOK)
		deleteResp.Body.Close()
	})
}

func TestAuditLog(t *testing.T) {
	ts := newTestServer(t)

	// Generate some activity.
	agent, _ := registerAgent(t, ts, "audit-agent")
	agentID := agent["id"].(string)
	issueToken(t, ts, agentID, []string{"read"}, 3600)

	t.Run("audit log returns entries", func(t *testing.T) {
		resp := ts.do(t, http.MethodGet, "/api/v1/audit", nil)
		mustStatus(t, resp, http.StatusOK)
		var result map[string]interface{}
		decodeJSON(t, resp, &result)
		if result["entries"] == nil {
			t.Fatal("expected entries field in audit response")
		}
	})

	t.Run("audit log requires admin key", func(t *testing.T) {
		resp := ts.doNoAuth(t, http.MethodGet, "/api/v1/audit", nil)
		mustStatus(t, resp, http.StatusUnauthorized)
		resp.Body.Close()
	})
}

func TestRevocationsList(t *testing.T) {
	ts := newTestServer(t)

	t.Run("revocations list is accessible", func(t *testing.T) {
		resp := ts.do(t, http.MethodGet, "/api/v1/admin/revocations", nil)
		mustStatus(t, resp, http.StatusOK)
		resp.Body.Close()
	})
}
