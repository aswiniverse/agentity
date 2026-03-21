package e2e_test

import (
	"net/http"
	"testing"

	agcrypto "github.com/agentity/agentity/pkg/crypto"
	"github.com/agentity/agentity/pkg/token"
)

// delegateLocally performs client-side delegation: the parent agent signs a new
// delegation block using its private key, then submits the full encoded token
// to the server for verification and audit logging.
func delegateLocally(
	t *testing.T,
	ts *testServer,
	parentTokenEncoded string,
	childAgentID string,
	parentPrivKeyB64 string,
	caps []string,
	ttlSecs int64,
) string {
	t.Helper()

	parentPrivKey, err := agcrypto.DecodePrivateKeyBase64(parentPrivKeyB64)
	if err != nil {
		t.Fatalf("decode parent private key: %v", err)
	}

	parentACT, err := token.Decode(parentTokenEncoded)
	if err != nil {
		t.Fatalf("decode parent token: %v", err)
	}

	delegated, err := token.Delegate(parentACT, childAgentID, caps, token.BlockConditions{
		ExpiresAt: futureExpiry(ttlSecs),
	}, parentPrivKey)
	if err != nil {
		t.Fatalf("local delegation: %v", err)
	}

	encoded, err := token.Encode(delegated)
	if err != nil {
		t.Fatalf("encode delegated token: %v", err)
	}

	// Submit to server for validation + audit.
	resp := ts.do(t, http.MethodPost, "/api/v1/tokens/delegate", map[string]interface{}{
		"delegated_token": encoded,
	})
	mustStatus(t, resp, http.StatusCreated)
	var result map[string]interface{}
	decodeJSON(t, resp, &result)
	return result["token"].(string)
}

func TestDelegationChain(t *testing.T) {
	ts := newTestServer(t)

	// Set up parent → child relationship.
	parent, parentPrivKey := registerAgent(t, ts, "deleg-parent")
	parentID := parent["id"].(string)

	child, _ := registerAgent(t, ts, "deleg-child")
	childID := child["id"].(string)

	// Issue a root token to the parent.
	parentToken := issueToken(t, ts, parentID, []string{"read", "write", "execute"}, 3600)

	t.Run("parent delegates subset of capabilities to child", func(t *testing.T) {
		delegatedToken := delegateLocally(t, ts, parentToken, childID, parentPrivKey,
			[]string{"read"}, 1800)

		// Verify the delegated token.
		resp := ts.do(t, http.MethodPost, "/api/v1/tokens/verify", map[string]interface{}{
			"token": delegatedToken,
		})
		mustStatus(t, resp, http.StatusOK)
		var verified map[string]interface{}
		decodeJSON(t, resp, &verified)

		if verified["agent_id"] != childID {
			t.Fatalf("expected agent_id=%s, got %v", childID, verified["agent_id"])
		}
		if verified["chain_depth"].(float64) != 2 {
			t.Fatalf("expected chain_depth=2, got %v", verified["chain_depth"])
		}
		caps := verified["capabilities"].([]interface{})
		if len(caps) != 1 || caps[0] != "read" {
			t.Fatalf("expected capabilities=[read], got %v", caps)
		}
	})

	t.Run("delegated token chain depth is correct", func(t *testing.T) {
		delegatedToken := delegateLocally(t, ts, parentToken, childID, parentPrivKey,
			[]string{"read", "write"}, 1800)

		resp := ts.do(t, http.MethodGet, "/api/v1/tokens/any/chain?token="+delegatedToken, nil)
		mustStatus(t, resp, http.StatusOK)
		var chain map[string]interface{}
		decodeJSON(t, resp, &chain)

		if chain["depth"].(float64) != 2 {
			t.Fatalf("expected depth=2 for delegated token chain, got %v", chain["depth"])
		}
	})
}

func TestDelegationCapabilityAttenuation(t *testing.T) {
	ts := newTestServer(t)

	parent, parentPrivKey := registerAgent(t, ts, "attenuation-parent")
	parentID := parent["id"].(string)
	child, _ := registerAgent(t, ts, "attenuation-child")
	childID := child["id"].(string)

	parentToken := issueToken(t, ts, parentID, []string{"read"}, 3600)

	t.Run("cannot amplify capabilities beyond parent", func(t *testing.T) {
		parentPrivKeyBytes, err := agcrypto.DecodePrivateKeyBase64(parentPrivKey)
		if err != nil {
			t.Fatalf("decode private key: %v", err)
		}
		parentACT, err := token.Decode(parentToken)
		if err != nil {
			t.Fatalf("decode parent token: %v", err)
		}

		// Try to delegate "write" which parent doesn't have.
		_, err = token.Delegate(parentACT, childID, []string{"write"}, token.BlockConditions{
			ExpiresAt: futureExpiry(1800),
		}, parentPrivKeyBytes)
		if err == nil {
			t.Fatal("expected capability amplification error, got nil")
		}
	})
}

func TestDelegationSubmitInvalid(t *testing.T) {
	ts := newTestServer(t)

	t.Run("submit empty delegated_token returns 400", func(t *testing.T) {
		resp := ts.do(t, http.MethodPost, "/api/v1/tokens/delegate", map[string]interface{}{
			"delegated_token": "",
		})
		mustStatus(t, resp, http.StatusBadRequest)
		resp.Body.Close()
	})

	t.Run("submit garbage token returns 400", func(t *testing.T) {
		resp := ts.do(t, http.MethodPost, "/api/v1/tokens/delegate", map[string]interface{}{
			"delegated_token": "totally-invalid-garbage",
		})
		mustStatus(t, resp, http.StatusBadRequest)
		resp.Body.Close()
	})
}

func TestThreeHopDelegationChain(t *testing.T) {
	ts := newTestServer(t)

	grandparent, gpPrivKey := registerAgent(t, ts, "gp")
	gpID := grandparent["id"].(string)

	parent, pPrivKey := registerAgent(t, ts, "parent")
	parentID := parent["id"].(string)

	child, _ := registerAgent(t, ts, "child")
	childID := child["id"].(string)

	// Issue root token to grandparent.
	gpToken := issueToken(t, ts, gpID, []string{"read", "write"}, 3600)

	// Grandparent → parent.
	parentToken := delegateLocally(t, ts, gpToken, parentID, gpPrivKey,
		[]string{"read", "write"}, 1800)

	// Parent → child (subset).
	childToken := delegateLocally(t, ts, parentToken, childID, pPrivKey,
		[]string{"read"}, 900)

	// Verify the 3-block token resolves to child with only "read".
	resp := ts.do(t, http.MethodPost, "/api/v1/tokens/verify", map[string]interface{}{
		"token": childToken,
	})
	mustStatus(t, resp, http.StatusOK)
	var verified map[string]interface{}
	decodeJSON(t, resp, &verified)

	if verified["agent_id"] != childID {
		t.Fatalf("expected agent_id=%s, got %v", childID, verified["agent_id"])
	}
	if verified["chain_depth"].(float64) != 3 {
		t.Fatalf("expected chain_depth=3, got %v", verified["chain_depth"])
	}
	caps := verified["capabilities"].([]interface{})
	if len(caps) != 1 || caps[0] != "read" {
		t.Fatalf("expected capabilities=[read], got %v", caps)
	}
	path := verified["delegation_path"].([]interface{})
	if len(path) != 3 {
		t.Fatalf("expected delegation_path length=3, got %d", len(path))
	}
}
