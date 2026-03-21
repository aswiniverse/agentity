package e2e_test

import (
	"net/http"
	"testing"
)

func TestOIDCDiscovery(t *testing.T) {
	ts := newTestServer(t)

	t.Run("openid-configuration is public", func(t *testing.T) {
		resp := ts.doNoAuth(t, http.MethodGet, "/.well-known/openid-configuration", nil)
		mustStatus(t, resp, http.StatusOK)
		var doc map[string]interface{}
		decodeJSON(t, resp, &doc)
		if doc["issuer"] == nil {
			t.Fatal("expected issuer in openid-configuration")
		}
		if doc["jwks_uri"] == nil {
			t.Fatal("expected jwks_uri in openid-configuration")
		}
	})

	t.Run("jwks endpoint returns public key set", func(t *testing.T) {
		resp := ts.doNoAuth(t, http.MethodGet, "/.well-known/jwks.json", nil)
		mustStatus(t, resp, http.StatusOK)
		var jwks map[string]interface{}
		decodeJSON(t, resp, &jwks)
		keys, ok := jwks["keys"].([]interface{})
		if !ok || len(keys) == 0 {
			t.Fatal("expected at least one key in JWKS")
		}
		key := keys[0].(map[string]interface{})
		if key["kty"] == nil {
			t.Fatal("expected kty in JWKS key")
		}
		if key["kid"] == nil {
			t.Fatal("expected kid in JWKS key")
		}
	})
}

func TestOAuthTokenExchange(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "oauth-agent")
	agentID := agent["id"].(string)

	actToken := issueToken(t, ts, agentID, []string{"read", "write"}, 3600)

	t.Run("token exchange with valid ACT returns JWT", func(t *testing.T) {
		resp := ts.doForm(t, "/oauth/token", map[string]string{
			"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token":      actToken,
			"subject_token_type": "urn:agentity:token-type:act",
		})
		mustStatus(t, resp, http.StatusOK)
		var result map[string]interface{}
		decodeJSON(t, resp, &result)
		if result["access_token"] == nil || result["access_token"] == "" {
			t.Fatal("expected access_token in token exchange response")
		}
		if result["token_type"] != "Bearer" {
			t.Fatalf("expected token_type=Bearer, got %v", result["token_type"])
		}
		if result["expires_in"] == nil {
			t.Fatal("expected expires_in in response")
		}
	})

	t.Run("unsupported grant_type returns error", func(t *testing.T) {
		resp := ts.doForm(t, "/oauth/token", map[string]string{
			"grant_type": "client_credentials",
		})
		mustStatus(t, resp, http.StatusBadRequest)
		var result map[string]interface{}
		decodeJSON(t, resp, &result)
		if result["error"] != "unsupported_grant_type" {
			t.Fatalf("expected error=unsupported_grant_type, got %v", result["error"])
		}
	})

	t.Run("wrong subject_token_type returns error", func(t *testing.T) {
		resp := ts.doForm(t, "/oauth/token", map[string]string{
			"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token":      actToken,
			"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
		})
		mustStatus(t, resp, http.StatusBadRequest)
		resp.Body.Close()
	})

	t.Run("invalid ACT token returns 401", func(t *testing.T) {
		resp := ts.doForm(t, "/oauth/token", map[string]string{
			"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token":      "invalid-token",
			"subject_token_type": "urn:agentity:token-type:act",
		})
		mustStatus(t, resp, http.StatusUnauthorized)
		resp.Body.Close()
	})
}

func TestOAuthIntrospect(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "introspect-agent")
	agentID := agent["id"].(string)

	actToken := issueToken(t, ts, agentID, []string{"read"}, 3600)

	t.Run("introspect valid token returns active=true", func(t *testing.T) {
		resp := ts.doForm(t, "/oauth/introspect", map[string]string{
			"token": actToken,
		})
		mustStatus(t, resp, http.StatusOK)
		var result map[string]interface{}
		decodeJSON(t, resp, &result)
		if result["active"] != true {
			t.Fatalf("expected active=true, got %v", result["active"])
		}
		if result["sub"] != agentID {
			t.Fatalf("expected sub=%s, got %v", agentID, result["sub"])
		}
	})

	t.Run("introspect invalid token returns active=false", func(t *testing.T) {
		resp := ts.doForm(t, "/oauth/introspect", map[string]string{
			"token": "garbage-token",
		})
		mustStatus(t, resp, http.StatusOK)
		var result map[string]interface{}
		decodeJSON(t, resp, &result)
		if result["active"] != false {
			t.Fatalf("expected active=false for invalid token, got %v", result["active"])
		}
	})

	t.Run("introspect missing token returns active=false", func(t *testing.T) {
		resp := ts.doForm(t, "/oauth/introspect", map[string]string{})
		mustStatus(t, resp, http.StatusOK)
		var result map[string]interface{}
		decodeJSON(t, resp, &result)
		if result["active"] != false {
			t.Fatalf("expected active=false when token missing, got %v", result["active"])
		}
	})
}

func TestOAuthRevoke(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "oauth-revoke-agent")
	agentID := agent["id"].(string)

	t.Run("revoke valid token returns 200", func(t *testing.T) {
		actToken := issueToken(t, ts, agentID, []string{"read"}, 3600)
		resp := ts.doForm(t, "/oauth/revoke", map[string]string{
			"token": actToken,
		})
		mustStatus(t, resp, http.StatusOK)
		resp.Body.Close()

		// After revocation, introspect should return active=false.
		introspect := ts.doForm(t, "/oauth/introspect", map[string]string{
			"token": actToken,
		})
		mustStatus(t, introspect, http.StatusOK)
		var result map[string]interface{}
		decodeJSON(t, introspect, &result)
		if result["active"] != false {
			t.Fatalf("expected active=false after oauth revoke, got %v", result["active"])
		}
	})

	t.Run("revoke unknown/invalid token still returns 200 (RFC 7009)", func(t *testing.T) {
		resp := ts.doForm(t, "/oauth/revoke", map[string]string{
			"token": "unknown-junk",
		})
		mustStatus(t, resp, http.StatusOK)
		resp.Body.Close()
	})

	t.Run("revoke with no token returns 200 (RFC 7009)", func(t *testing.T) {
		resp := ts.doForm(t, "/oauth/revoke", map[string]string{})
		mustStatus(t, resp, http.StatusOK)
		resp.Body.Close()
	})
}

func TestUserInfo(t *testing.T) {
	ts := newTestServer(t)

	t.Run("userinfo endpoint is reachable", func(t *testing.T) {
		// The userinfo endpoint is public; it may return 401 without a token
		// but the route must exist (not 404).
		resp := ts.doNoAuth(t, http.MethodGet, "/oidc/userinfo", nil)
		if resp.StatusCode == http.StatusNotFound {
			t.Fatal("userinfo endpoint returned 404 - route not registered")
		}
		resp.Body.Close()
	})
}
