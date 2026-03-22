package mcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// OAuthConfig holds OAuth 2.1 configuration for MCP servers.
type OAuthConfig struct {
	Issuer            string   // OAuth server issuer URL (e.g. "https://auth.example.com")
	ClientID          string   // OAuth client ID
	AuthorizationURL  string   // Authorization endpoint URL
	TokenURL          string   // Token endpoint URL
	ResourceIndicator string   // RFC 8707 resource indicator (e.g. "https://mcp.example.com")
	Scopes            []string // Required scopes (e.g. ["mcp:tools"])
}

// OAuthTokenResponse is the token endpoint response.
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// GenerateCodeVerifier generates a cryptographically random PKCE code verifier.
// The verifier is 32 random bytes encoded as base64url (no padding), producing a
// 43-character string as recommended by RFC 7636.
func GenerateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate code verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ComputeCodeChallenge computes the S256 code challenge from a verifier.
// challenge = BASE64URL(SHA256(ASCII(verifier)))
func ComputeCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// GenerateAuthorizationURL builds an OAuth 2.1 authorization URL with:
//   - PKCE: code_challenge_method=S256, code_challenge=BASE64URL(SHA256(codeVerifier))
//   - resource parameter per RFC 8707
//   - state parameter for CSRF protection
//   - response_type=code
func GenerateAuthorizationURL(config OAuthConfig, state, codeVerifier string) (string, error) {
	if config.AuthorizationURL == "" {
		return "", fmt.Errorf("AuthorizationURL is required")
	}
	if config.ClientID == "" {
		return "", fmt.Errorf("ClientID is required")
	}

	challenge := ComputeCodeChallenge(codeVerifier)

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", config.ClientID)
	params.Set("state", state)
	params.Set("code_challenge_method", "S256")
	params.Set("code_challenge", challenge)
	if config.ResourceIndicator != "" {
		params.Set("resource", config.ResourceIndicator)
	}
	if len(config.Scopes) > 0 {
		params.Set("scope", strings.Join(config.Scopes, " "))
	}

	base := config.AuthorizationURL
	if strings.Contains(base, "?") {
		return base + "&" + params.Encode(), nil
	}
	return base + "?" + params.Encode(), nil
}

// ExchangeCodeForToken exchanges an authorization code for tokens.
// Sends code_verifier (PKCE) and resource parameter in the token request.
func ExchangeCodeForToken(ctx context.Context, config OAuthConfig, code, codeVerifier string) (*OAuthTokenResponse, error) {
	if config.TokenURL == "" {
		return nil, fmt.Errorf("TokenURL is required")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", config.ClientID)
	form.Set("code_verifier", codeVerifier)
	if config.ResourceIndicator != "" {
		form.Set("resource", config.ResourceIndicator)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var tokenResp OAuthTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	return &tokenResp, nil
}
