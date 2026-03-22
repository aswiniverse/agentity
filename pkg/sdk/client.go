package sdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/agentity/agentity/internal/identity"
	"github.com/agentity/agentity/pkg/token"
)

// Client is the Go SDK client for the Agentity API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	adminKey   string
}

// NewClient creates a new Agentity SDK client.
func NewClient(baseURL, adminKey string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		adminKey: adminKey,
	}
}

// RegisterAgentRequest is the input for registering an agent.
type RegisterAgentRequest struct {
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	Version      string            `json:"version,omitempty"`
	SystemPrompt string            `json:"system_prompt,omitempty"`
	Tools        []string          `json:"tools,omitempty"`
	Model        string            `json:"model,omitempty"`
	ParentID     string            `json:"parent_id,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// RegisterAgentResponse contains the agent and its private key.
type RegisterAgentResponse struct {
	Agent      *identity.AgentIdentity `json:"agent"`
	PrivateKey string                  `json:"private_key"`
}

// RegisterAgent registers a new agent and returns the identity with its private key.
func (c *Client) RegisterAgent(ctx context.Context, req RegisterAgentRequest) (*identity.AgentIdentity, string, error) {
	var resp RegisterAgentResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/agents", req, &resp); err != nil {
		return nil, "", err
	}
	return resp.Agent, resp.PrivateKey, nil
}

// GetAgent retrieves an agent by its full ID (agent://uuid).
func (c *Client) GetAgent(ctx context.Context, id string) (*identity.AgentIdentity, error) {
	// Strip the "agent://" prefix for the URL path.
	urlID := id
	if len(id) > 8 && id[:8] == "agent://" {
		urlID = id[8:]
	}
	var agent identity.AgentIdentity
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/agents/"+urlID, nil, &agent); err != nil {
		return nil, err
	}
	return &agent, nil
}

// RevokeAgent revokes an agent, optionally cascading to children.
func (c *Client) RevokeAgent(ctx context.Context, id string, cascade bool) error {
	urlID := id
	if len(id) > 8 && id[:8] == "agent://" {
		urlID = id[8:]
	}
	body := map[string]bool{"cascade": cascade}
	return c.doJSON(ctx, http.MethodPost, "/api/v1/agents/"+urlID+"/revoke", body, nil)
}

// IssueTokenRequest is the input for issuing a root token.
type IssueTokenRequest struct {
	AgentID      string               `json:"agent_id"`
	Capabilities []string             `json:"capabilities"`
	Conditions   token.BlockConditions `json:"conditions"`
}

// IssueTokenResponse contains the encoded token and its ID.
type IssueTokenResponse struct {
	Token   string `json:"token"`
	TokenID string `json:"token_id"`
}

// IssueToken issues a root token for an agent.
func (c *Client) IssueToken(ctx context.Context, req IssueTokenRequest) (string, error) {
	var resp IssueTokenResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/tokens/issue", req, &resp); err != nil {
		return "", err
	}
	return resp.Token, nil
}

// submitDelegatedTokenRequest is the body sent when submitting a pre-signed delegated token.
type submitDelegatedTokenRequest struct {
	DelegatedToken string `json:"delegated_token"`
}

// SubmitDelegatedToken posts a pre-signed, locally-built delegated token to the server.
// The private key never leaves the caller's process.
func (c *Client) SubmitDelegatedToken(ctx context.Context, encodedToken string) error {
	body := submitDelegatedTokenRequest{DelegatedToken: encodedToken}
	return c.doJSON(ctx, http.MethodPost, "/api/v1/tokens/delegate", body, nil)
}

// DelegateTokenLocally signs a delegation block locally using the caller's private key
// and submits the resulting token to the server. No private key is sent over the wire.
func (c *Client) DelegateTokenLocally(
	ctx context.Context,
	parentToken string,
	childAgentID string,
	capabilities []string,
	conditions token.BlockConditions,
	parentPrivateKey ed25519.PrivateKey,
) (string, error) {
	parentACT, err := token.Decode(parentToken)
	if err != nil {
		return "", fmt.Errorf("decode parent token: %w", err)
	}

	delegatedACT, err := token.Delegate(parentACT, childAgentID, capabilities, conditions, parentPrivateKey)
	if err != nil {
		return "", fmt.Errorf("delegate token: %w", err)
	}

	encodedToken, err := token.Encode(delegatedACT)
	if err != nil {
		return "", fmt.Errorf("encode delegated token: %w", err)
	}

	if err := c.SubmitDelegatedToken(ctx, encodedToken); err != nil {
		return "", fmt.Errorf("submit delegated token: %w", err)
	}

	return encodedToken, nil
}

// VerifyTokenResponse contains the verified token details.
type VerifyTokenResponse struct {
	TokenID        string   `json:"token_id"`
	AgentID        string   `json:"agent_id"`
	Capabilities   []string `json:"capabilities"`
	ExpiresAt      int64    `json:"expires_at"`
	ChainDepth     int      `json:"chain_depth"`
	DelegationPath []string `json:"delegation_path"`
}

// VerifyToken verifies an encoded token.
func (c *Client) VerifyToken(ctx context.Context, encoded string) (*VerifyTokenResponse, error) {
	body := map[string]string{"token": encoded}
	var resp VerifyTokenResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/tokens/verify", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RevokeToken revokes a token by its ID.
func (c *Client) RevokeToken(ctx context.Context, tokenID, reason string) error {
	body := map[string]string{"token_id": tokenID, "reason": reason}
	return c.doJSON(ctx, http.MethodPost, "/api/v1/tokens/revoke", body, nil)
}

func (c *Client) doJSON(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.adminKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var problem map[string]interface{}
		if err := json.Unmarshal(respBody, &problem); err == nil {
			if detail, ok := problem["detail"].(string); ok {
				return fmt.Errorf("API error %d: %s", resp.StatusCode, detail)
			}
		}
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("unmarshal response: %w", err)
		}
	}

	return nil
}
