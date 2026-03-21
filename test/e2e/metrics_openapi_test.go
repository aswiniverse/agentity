package e2e_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// --- Prometheus metrics ---

func TestMetricsEndpoint_ReturnsPrometheusText(t *testing.T) {
	ts := newTestServer(t)

	// Generate some activity so counters are non-zero.
	agent, _ := registerAgent(t, ts, "metrics-agent")
	agentID := agent["id"].(string)
	issueToken(t, ts, agentID, []string{"read"}, 3600)

	resp := ts.doNoAuth(t, http.MethodGet, "/metrics", nil)
	mustStatus(t, resp, http.StatusOK)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read metrics body: %v", err)
	}
	text := string(body)

	// Prometheus text format includes HELP and TYPE lines for registered metrics.
	for _, expected := range []string{
		"agentity_tokens_issued_total",
		"agentity_agents_registered_total",
		"agentity_token_verification_duration_seconds",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("expected metric %q in /metrics output", expected)
		}
	}
}

func TestMetricsEndpoint_NoAuthRequired(t *testing.T) {
	ts := newTestServer(t)
	resp := ts.doNoAuth(t, http.MethodGet, "/metrics", nil)
	mustStatus(t, resp, http.StatusOK)
	resp.Body.Close()
}

func TestMetricsEndpoint_CountersIncrementOnActivity(t *testing.T) {
	ts := newTestServer(t)

	// Register an agent and issue a token — counters should appear.
	agent, _ := registerAgent(t, ts, "counter-agent")
	agentID := agent["id"].(string)
	tok := issueToken(t, ts, agentID, []string{"read"}, 3600)

	// Verify the token — tokens_verified_total should appear.
	verifyResp := ts.do(t, http.MethodPost, "/api/v1/tokens/verify", map[string]interface{}{
		"token": tok,
	})
	mustStatus(t, verifyResp, http.StatusOK)
	verifyResp.Body.Close()

	resp := ts.doNoAuth(t, http.MethodGet, "/metrics", nil)
	mustStatus(t, resp, http.StatusOK)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if !strings.Contains(string(body), "agentity_tokens_verified_total") {
		t.Error("expected agentity_tokens_verified_total in metrics after verification")
	}
}

// --- OpenAPI spec ---

func TestOpenAPISpec_Returns200(t *testing.T) {
	ts := newTestServer(t)
	resp := ts.doNoAuth(t, http.MethodGet, "/api/v1/openapi.json", nil)
	mustStatus(t, resp, http.StatusOK)
	resp.Body.Close()
}

func TestOpenAPISpec_NoAuthRequired(t *testing.T) {
	ts := newTestServer(t)
	// Should be accessible without admin key.
	resp := ts.doNoAuth(t, http.MethodGet, "/api/v1/openapi.json", nil)
	mustStatus(t, resp, http.StatusOK)
	resp.Body.Close()
}

func TestOpenAPISpec_ValidJSON(t *testing.T) {
	ts := newTestServer(t)
	resp := ts.doNoAuth(t, http.MethodGet, "/api/v1/openapi.json", nil)
	mustStatus(t, resp, http.StatusOK)
	defer resp.Body.Close()

	var spec map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&spec); err != nil {
		t.Fatalf("expected valid JSON from /api/v1/openapi.json: %v", err)
	}
}

func TestOpenAPISpec_HasRequiredFields(t *testing.T) {
	ts := newTestServer(t)
	resp := ts.doNoAuth(t, http.MethodGet, "/api/v1/openapi.json", nil)
	mustStatus(t, resp, http.StatusOK)

	var spec map[string]interface{}
	decodeJSON(t, resp, &spec)

	for _, field := range []string{"openapi", "info", "paths", "components"} {
		if spec[field] == nil {
			t.Errorf("expected field %q in OpenAPI spec", field)
		}
	}
	if spec["openapi"] != "3.1.0" {
		t.Errorf("expected openapi=3.1.0, got %v", spec["openapi"])
	}
}

func TestOpenAPISpec_PathsContainKeyEndpoints(t *testing.T) {
	ts := newTestServer(t)
	resp := ts.doNoAuth(t, http.MethodGet, "/api/v1/openapi.json", nil)
	mustStatus(t, resp, http.StatusOK)

	var spec map[string]interface{}
	decodeJSON(t, resp, &spec)

	paths, ok := spec["paths"].(map[string]interface{})
	if !ok {
		t.Fatal("paths field is not an object")
	}

	required := []string{
		"/api/v1/agents",
		"/api/v1/tokens/issue",
		"/api/v1/tokens/verify",
		"/api/v1/tokens/delegate",
		"/oauth/token",
		"/.well-known/openid-configuration",
	}
	for _, path := range required {
		if paths[path] == nil {
			t.Errorf("expected path %q in OpenAPI spec", path)
		}
	}
}

func TestOpenAPISpec_ContentTypeIsJSON(t *testing.T) {
	ts := newTestServer(t)
	resp := ts.doNoAuth(t, http.MethodGet, "/api/v1/openapi.json", nil)
	mustStatus(t, resp, http.StatusOK)
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("expected Content-Type: application/json, got %s", ct)
	}
}

func TestSwaggerUI_Redirects(t *testing.T) {
	ts := newTestServer(t)

	// Don't follow redirects so we can inspect the 302.
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/docs", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /docs: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 redirect from /docs, got %d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	if !strings.Contains(location, "swagger") && !strings.Contains(location, "petstore") {
		t.Fatalf("expected redirect to Swagger UI, got %s", location)
	}
}
