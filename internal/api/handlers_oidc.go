package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/agentity/agentity/internal/delegation"
	agcrypto "github.com/agentity/agentity/pkg/crypto"
)

// OIDCHandlers provides OpenID Connect discovery endpoints.
type OIDCHandlers struct {
	rootKeyStore     *agcrypto.RootKeyStore
	delegationEngine *delegation.Engine
	issuerURL        string
}

// NewOIDCHandlers creates new OIDC handlers.
func NewOIDCHandlers(rootKeyStore *agcrypto.RootKeyStore, engine *delegation.Engine, issuerURL string) *OIDCHandlers {
	return &OIDCHandlers{
		rootKeyStore:     rootKeyStore,
		delegationEngine: engine,
		issuerURL:        issuerURL,
	}
}

// OpenIDConfiguration handles GET /.well-known/openid-configuration
func (h *OIDCHandlers) OpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	issuer := h.issuerURL
	if issuer == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		issuer = fmt.Sprintf("%s://%s", scheme, r.Host)
	}

	config := map[string]interface{}{
		"issuer":                                issuer,
		"token_endpoint":                        issuer + "/oauth/token",
		"introspection_endpoint":                issuer + "/oauth/introspect",
		"revocation_endpoint":                   issuer + "/oauth/revoke",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"userinfo_endpoint":                     issuer + "/oidc/userinfo",
		"response_types_supported":              []string{"token"},
		"grant_types_supported":                 []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic"},
		"scopes_supported":                      []string{"openid", "agent:read", "agent:write"},
		"claims_supported": []string{
			"sub", "iss", "exp", "iat", "jti",
			"caps", "depth", "path",
			"agent_model", "agent_fingerprint",
		},
	}

	writeJSON(w, http.StatusOK, config)
}

// JWKSEndpoint handles GET /.well-known/jwks.json
func (h *OIDCHandlers) JWKSEndpoint(w http.ResponseWriter, _ *http.Request) {
	pub := h.rootKeyStore.PublicKey()

	// Ed25519 public key in JWK format (OKP).
	jwk := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(ed25519.PublicKey(pub)),
		"kid": h.rootKeyStore.KeyID(),
		"use": "sig",
		"alg": "EdDSA",
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"keys": []interface{}{jwk},
	})
}

// UserInfo handles GET /oidc/userinfo
// Requires an ACT token in the Authorization header.
func (h *OIDCHandlers) UserInfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		writeProblem(w, http.StatusUnauthorized, "https://agentity.dev/errors/unauthorized", "Unauthorized", "Missing Authorization header")
		return
	}

	tokenStr := strings.TrimPrefix(auth, "Bearer ")

	verified, err := h.delegationEngine.Verify(r.Context(), tokenStr)
	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "https://agentity.dev/errors/token-invalid", "Token Invalid", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sub":             verified.AgentID,
		"capabilities":    verified.Capabilities,
		"chain_depth":     verified.ChainDepth,
		"delegation_path": verified.DelegationPath,
		"token_id":        verified.TokenID,
		"expires_at":      verified.ExpiresAt,
	})
}
