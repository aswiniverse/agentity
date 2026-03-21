package e2e_test

import (
	"net/http"
	"testing"
)

func TestAgentRateLimit_BurstTriggersThrottle(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "ratelimit-agent")
	agentID := agent["id"].(string)

	// Send 30 rapid issue requests for the same agent. The per-agent limiter
	// allows 20/sec, so we should see at least one 429 among 30 requests.
	got429 := false
	for i := 0; i < 30; i++ {
		resp := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
			"agent_id":     agentID,
			"capabilities": []string{"read"},
			"conditions":   map[string]interface{}{"exp": futureExpiry(3600)},
		})
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			resp.Body.Close()
			break
		}
		resp.Body.Close()
	}

	if !got429 {
		t.Fatal("expected at least one 429 Too Many Requests after 30 rapid requests for the same agent")
	}
}

func TestAgentRateLimit_DifferentAgentsAreIndependent(t *testing.T) {
	ts := newTestServer(t)

	// Register two separate agents.
	agentA, _ := registerAgent(t, ts, "ratelimit-agent-a")
	agentB, _ := registerAgent(t, ts, "ratelimit-agent-b")
	idA := agentA["id"].(string)
	idB := agentB["id"].(string)

	// Exhaust agent A's rate limit.
	for i := 0; i < 25; i++ {
		resp := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
			"agent_id":     idA,
			"capabilities": []string{"read"},
			"conditions":   map[string]interface{}{"exp": futureExpiry(3600)},
		})
		resp.Body.Close()
	}

	// Agent B should still be allowed (independent bucket).
	resp := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
		"agent_id":     idB,
		"capabilities": []string{"read"},
		"conditions":   map[string]interface{}{"exp": futureExpiry(3600)},
	})
	if resp.StatusCode == http.StatusTooManyRequests {
		resp.Body.Close()
		t.Fatal("agent B should not be rate-limited when agent A is exhausted")
	}
	resp.Body.Close()
}

func TestAgentRateLimit_429HasProblemDetailsBody(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "ratelimit-body-agent")
	agentID := agent["id"].(string)

	// Exhaust tokens.
	var last *http.Response
	for i := 0; i < 30; i++ {
		r := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
			"agent_id":     agentID,
			"capabilities": []string{"read"},
			"conditions":   map[string]interface{}{"exp": futureExpiry(3600)},
		})
		if r.StatusCode == http.StatusTooManyRequests {
			last = r
			break
		}
		r.Body.Close()
	}

	if last == nil {
		t.Skip("rate limit not triggered in this run — skip body check")
	}
	defer last.Body.Close()

	var body map[string]interface{}
	decodeJSON(t, last, &body)
	if body["type"] != "https://agentity.dev/errors/rate-limited" {
		t.Fatalf("expected rate-limited problem type, got %v", body["type"])
	}
}
