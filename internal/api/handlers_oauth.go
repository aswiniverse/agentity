package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/agentity/agentity/internal/delegation"
	"github.com/agentity/agentity/internal/revocation"
	"github.com/agentity/agentity/pkg/token"
	"github.com/golang-jwt/jwt/v5"

	agcrypto "github.com/agentity/agentity/pkg/crypto"
)

// OAuthHandlers provides OAuth2.1-compatible endpoints.
type OAuthHandlers struct {
	rootKeyStore     *agcrypto.RootKeyStore
	delegationEngine *delegation.Engine
	revocationReg    *revocation.Registry
}

// NewOAuthHandlers creates new OAuth handlers.
func NewOAuthHandlers(rootKeyStore *agcrypto.RootKeyStore, engine *delegation.Engine, rev *revocation.Registry) *OAuthHandlers {
	return &OAuthHandlers{
		rootKeyStore:     rootKeyStore,
		delegationEngine: engine,
		revocationReg:    rev,
	}
}

// TokenEndpoint handles POST /oauth/token
// Supports grant_type=urn:ietf:params:oauth:grant-type:token-exchange (RFC 8693).
func (h *OAuthHandlers) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Failed to parse form data")
		return
	}

	switch r.FormValue("grant_type") {
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		h.handleTokenExchange(w, r)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "Only token-exchange grant type is supported")
	}
}

func (h *OAuthHandlers) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	subjectToken := r.FormValue("subject_token")
	subjectTokenType := r.FormValue("subject_token_type")

	if subjectToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "subject_token is required")
		return
	}
	if subjectTokenType != "urn:agentity:token-type:act" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "subject_token_type must be urn:agentity:token-type:act")
		return
	}

	verified, err := h.delegationEngine.Verify(r.Context(), subjectToken)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_grant", "Token verification failed: "+err.Error())
		return
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   "agentity://server",
		"sub":   verified.AgentID,
		"aud":   "agentity",
		"exp":   verified.ExpiresAt,
		"iat":   now.Unix(),
		"jti":   verified.TokenID,
		"caps":  verified.Capabilities,
		"depth": verified.ChainDepth,
		"path":  verified.DelegationPath,
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	jwtToken.Header["kid"] = h.rootKeyStore.KeyID()

	signed, err := jwtToken.SignedString(h.rootKeyStore.PrivateKey())
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to sign JWT")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token":      signed,
		"token_type":        "Bearer",
		"expires_in":        verified.ExpiresAt - now.Unix(),
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
	})
}

// IntrospectEndpoint handles POST /oauth/introspect (RFC 7662).
func (h *OAuthHandlers) IntrospectEndpoint(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Failed to parse form data")
		return
	}

	tok := r.FormValue("token")
	if tok == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"active": false})
		return
	}

	verified, err := h.delegationEngine.Verify(r.Context(), tok)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"active": false})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"active":     true,
		"sub":        verified.AgentID,
		"exp":        verified.ExpiresAt,
		"iss":        "agentity://server",
		"token_type": "act",
		"caps":       verified.Capabilities,
		"depth":      verified.ChainDepth,
	})
}

// RevokeEndpoint handles POST /oauth/revoke (RFC 7009).
// C3 fix: actually revokes the token instead of silently discarding it.
func (h *OAuthHandlers) RevokeEndpoint(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Failed to parse form data")
		return
	}

	tok := r.FormValue("token")
	if tok == "" {
		// Per RFC 7009, return 200 even if token is not provided.
		w.WriteHeader(http.StatusOK)
		return
	}

	act, err := token.Decode(tok)
	if err != nil {
		// Per RFC 7009, return 200 for invalid/unknown tokens.
		w.WriteHeader(http.StatusOK)
		return
	}

	// C3 fix: actually revoke the token.
	if err := h.revocationReg.RevokeToken(r.Context(), act.TokenID, "oauth-revoke"); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to revoke token")
		return
	}

	w.WriteHeader(http.StatusOK)
}

func writeOAuthError(w http.ResponseWriter, status int, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}
