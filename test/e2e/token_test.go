package e2e_test

import (
	"net/http"
	"testing"

	"github.com/agentity/agentity/pkg/token"
)

func TestTokenIssuance(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "token-issuer")
	agentID := agent["id"].(string)

	t.Run("issue token for active agent", func(t *testing.T) {
		resp := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
			"agent_id":     agentID,
			"capabilities": []string{"read", "write"},
			"conditions": token.BlockConditions{
				ExpiresAt: futureExpiry(3600),
			},
		})
		mustStatus(t, resp, http.StatusCreated)
		var result map[string]interface{}
		decodeJSON(t, resp, &result)
		if result["token"] == nil || result["token"] == "" {
			t.Fatal("expected token in response")
		}
		if result["token_id"] == nil || result["token_id"] == "" {
			t.Fatal("expected token_id in response")
		}
	})

	t.Run("issue token without agent_id returns 400", func(t *testing.T) {
		resp := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
			"capabilities": []string{"read"},
			"conditions": token.BlockConditions{
				ExpiresAt: futureExpiry(3600),
			},
		})
		mustStatus(t, resp, http.StatusBadRequest)
		resp.Body.Close()
	})

	t.Run("issue token without capabilities returns 400", func(t *testing.T) {
		resp := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
			"agent_id":     agentID,
			"capabilities": []string{},
			"conditions": token.BlockConditions{
				ExpiresAt: futureExpiry(3600),
			},
		})
		mustStatus(t, resp, http.StatusBadRequest)
		resp.Body.Close()
	})

	t.Run("issue token for unknown agent returns 404", func(t *testing.T) {
		resp := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
			"agent_id":     "agent://00000000-0000-0000-0000-000000000000",
			"capabilities": []string{"read"},
			"conditions": token.BlockConditions{
				ExpiresAt: futureExpiry(3600),
			},
		})
		mustStatus(t, resp, http.StatusNotFound)
		resp.Body.Close()
	})

	t.Run("cannot issue token for suspended agent", func(t *testing.T) {
		suspended, _ := registerAgent(t, ts, "suspended-token-agent")
		suspendedID := suspended["id"].(string)
		suspendResp := ts.do(t, http.MethodPost, "/api/v1/agents/"+agentUUID(suspendedID)+"/suspend", nil)
		mustStatus(t, suspendResp, http.StatusOK)
		suspendResp.Body.Close()

		resp := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
			"agent_id":     suspendedID,
			"capabilities": []string{"read"},
			"conditions": token.BlockConditions{
				ExpiresAt: futureExpiry(3600),
			},
		})
		mustStatus(t, resp, http.StatusForbidden)
		resp.Body.Close()
	})

	t.Run("cannot issue token for revoked agent", func(t *testing.T) {
		revoked, _ := registerAgent(t, ts, "revoked-token-agent")
		revokedID := revoked["id"].(string)
		revokeResp := ts.do(t, http.MethodPost, "/api/v1/agents/"+agentUUID(revokedID)+"/revoke", nil)
		mustStatus(t, revokeResp, http.StatusOK)
		revokeResp.Body.Close()

		resp := ts.do(t, http.MethodPost, "/api/v1/tokens/issue", map[string]interface{}{
			"agent_id":     revokedID,
			"capabilities": []string{"read"},
			"conditions": token.BlockConditions{
				ExpiresAt: futureExpiry(3600),
			},
		})
		mustStatus(t, resp, http.StatusForbidden)
		resp.Body.Close()
	})
}

func TestTokenVerification(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "verify-agent")
	agentID := agent["id"].(string)

	t.Run("verify valid token", func(t *testing.T) {
		tok := issueToken(t, ts, agentID, []string{"read", "write"}, 3600)

		resp := ts.do(t, http.MethodPost, "/api/v1/tokens/verify", map[string]interface{}{
			"token": tok,
		})
		mustStatus(t, resp, http.StatusOK)
		var verified map[string]interface{}
		decodeJSON(t, resp, &verified)
		if verified["agent_id"] != agentID {
			t.Fatalf("expected agent_id=%s, got %v", agentID, verified["agent_id"])
		}
		if verified["chain_depth"].(float64) != 1 {
			t.Fatalf("expected chain_depth=1 for root token, got %v", verified["chain_depth"])
		}
		caps := verified["capabilities"].([]interface{})
		if len(caps) == 0 {
			t.Fatal("expected non-empty capabilities in verified token")
		}
	})

	t.Run("verify malformed token returns 401", func(t *testing.T) {
		resp := ts.do(t, http.MethodPost, "/api/v1/tokens/verify", map[string]interface{}{
			"token": "not-a-valid-token",
		})
		mustStatus(t, resp, http.StatusUnauthorized)
		resp.Body.Close()
	})

	t.Run("verify empty token returns 400", func(t *testing.T) {
		resp := ts.do(t, http.MethodPost, "/api/v1/tokens/verify", map[string]interface{}{
			"token": "",
		})
		mustStatus(t, resp, http.StatusBadRequest)
		resp.Body.Close()
	})
}

func TestTokenRevocation(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "revoke-token-agent")
	agentID := agent["id"].(string)

	t.Run("revoke token makes it invalid", func(t *testing.T) {
		tok := issueToken(t, ts, agentID, []string{"read"}, 3600)

		// Decode to get token_id.
		act, err := token.Decode(tok)
		if err != nil {
			t.Fatalf("decode token: %v", err)
		}
		tokenID := act.TokenID

		// Revoke it.
		revokeResp := ts.do(t, http.MethodPost, "/api/v1/tokens/revoke", map[string]interface{}{
			"token_id": tokenID,
			"reason":   "test revocation",
		})
		mustStatus(t, revokeResp, http.StatusOK)
		revokeResp.Body.Close()

		// Verify should now fail.
		verifyResp := ts.do(t, http.MethodPost, "/api/v1/tokens/verify", map[string]interface{}{
			"token": tok,
		})
		mustStatus(t, verifyResp, http.StatusUnauthorized)
		verifyResp.Body.Close()
	})

	t.Run("revoke without token_id returns 400", func(t *testing.T) {
		resp := ts.do(t, http.MethodPost, "/api/v1/tokens/revoke", map[string]interface{}{
			"reason": "missing token_id",
		})
		mustStatus(t, resp, http.StatusBadRequest)
		resp.Body.Close()
	})
}

func TestGetTokenChain(t *testing.T) {
	ts := newTestServer(t)
	agent, _ := registerAgent(t, ts, "chain-agent")
	agentID := agent["id"].(string)

	tok := issueToken(t, ts, agentID, []string{"read"}, 3600)

	// GetChain reads the token query parameter.
	resp := ts.do(t, http.MethodGet, "/api/v1/tokens/any/chain?token="+tok, nil)
	mustStatus(t, resp, http.StatusOK)
	var chain map[string]interface{}
	decodeJSON(t, resp, &chain)
	if chain["depth"].(float64) != 1 {
		t.Fatalf("expected depth=1, got %v", chain["depth"])
	}
	blocks := chain["blocks"].([]interface{})
	if len(blocks) != 1 {
		t.Fatalf("expected 1 block in chain, got %d", len(blocks))
	}
}
