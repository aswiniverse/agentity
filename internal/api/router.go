package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/agentity/agentity/internal/audit"
	"github.com/agentity/agentity/internal/delegation"
	"github.com/agentity/agentity/internal/identity"
	"github.com/agentity/agentity/internal/policy"
	"github.com/agentity/agentity/internal/revocation"
	agcrypto "github.com/agentity/agentity/pkg/crypto"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
)

// RouterConfig holds all dependencies needed to build the API router.
type RouterConfig struct {
	Logger           zerolog.Logger
	RootKeyStore     *agcrypto.RootKeyStore
	IdentityService  *identity.Service
	DelegationEngine *delegation.Engine
	RevocationReg    *revocation.Registry
	PolicyEngine     *policy.Engine
	AuditLogger      *audit.Logger
	AdminAPIKey      string
	IssuerURL        string
	// AllowedOrigins controls CORS. Use ["*"] for dev, explicit origins for prod.
	AllowedOrigins []string
	// ReadinessCheck is called by GET /ready to verify dependencies are healthy.
	ReadinessCheck func() error
}

// NewRouter creates the chi router with all routes and middleware wired.
func NewRouter(cfg RouterConfig) *chi.Mux {
	r := chi.NewRouter()

	if len(cfg.AllowedOrigins) == 0 {
		cfg.AllowedOrigins = []string{"*"}
	}

	// Global middleware.
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.RealIP)
	r.Use(RequestIDMiddleware)
	r.Use(LoggingMiddleware(cfg.Logger))
	r.Use(CORSMiddleware(cfg.AllowedOrigins))
	r.Use(MaxBytesMiddleware)

	// Rate limiting: 100 requests per second per IP.
	limiter := NewRateLimiter(100, time.Second)
	r.Use(limiter.Middleware)

	// Liveness: always returns 200 (process is running).
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Readiness: checks that dependencies (DB, Redis) are reachable.
	r.Get("/ready", func(w http.ResponseWriter, r *http.Request) {
		if cfg.ReadinessCheck != nil {
			if err := cfg.ReadinessCheck(); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{
					"status": "unavailable",
					"reason": err.Error(),
				})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})

	// OIDC discovery endpoints (public).
	oidcHandlers := NewOIDCHandlers(cfg.RootKeyStore, cfg.DelegationEngine, cfg.IssuerURL)
	r.Get("/.well-known/openid-configuration", oidcHandlers.OpenIDConfiguration)
	r.Get("/.well-known/jwks.json", oidcHandlers.JWKSEndpoint)
	r.Get("/oidc/userinfo", oidcHandlers.UserInfo)

	// OAuth2 endpoints (public).
	// C3 fix: revocationReg is now wired so RevokeEndpoint actually revokes.
	oauthHandlers := NewOAuthHandlers(cfg.RootKeyStore, cfg.DelegationEngine, cfg.RevocationReg)
	r.Post("/oauth/token", oauthHandlers.TokenEndpoint)
	r.Post("/oauth/introspect", oauthHandlers.IntrospectEndpoint)
	r.Post("/oauth/revoke", oauthHandlers.RevokeEndpoint)

	// API v1 routes (admin-protected).
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(AdminAuthMiddleware(cfg.AdminAPIKey))

		// Identity endpoints.
		idHandlers := NewIdentityHandlers(cfg.IdentityService)
		r.Post("/agents", idHandlers.RegisterAgent)
		r.Get("/agents", idHandlers.ListAgents)
		r.Get("/agents/{id}", idHandlers.GetAgent)
		r.Get("/agents/{id}/tree", idHandlers.GetDelegationTree)
		r.Post("/agents/{id}/suspend", idHandlers.SuspendAgent)
		r.Post("/agents/{id}/revoke", idHandlers.RevokeAgent)
		r.Post("/agents/{id}/rotate-key", idHandlers.RotateKey)

		// Token endpoints.
		// C4 fix: identityService wired so IssueToken verifies agent existence.
		// C4 fix: DelegateToken replaced by SubmitDelegatedToken — no private keys over the wire.
		tokenHandlers := NewTokenHandlers(
			cfg.RootKeyStore,
			cfg.DelegationEngine,
			cfg.RevocationReg,
			cfg.AuditLogger,
			cfg.IdentityService,
		)
		r.Post("/tokens/issue", tokenHandlers.IssueToken)
		r.Post("/tokens/delegate", tokenHandlers.SubmitDelegatedToken)
		r.Post("/tokens/verify", tokenHandlers.VerifyToken)
		r.Post("/tokens/revoke", tokenHandlers.RevokeToken)
		r.Get("/tokens/{id}/chain", tokenHandlers.GetChain)

		// Admin endpoints.
		adminHandlers := NewAdminHandlers(cfg.IdentityService, cfg.PolicyEngine, cfg.RevocationReg, cfg.AuditLogger)
		r.Get("/admin/stats", adminHandlers.Stats)
		r.Get("/admin/policies", adminHandlers.ListPolicies)
		r.Post("/admin/policies", adminHandlers.CreatePolicy)
		r.Delete("/admin/policies/{id}", adminHandlers.DeletePolicy)
		r.Get("/admin/revocations", adminHandlers.ListRevocations)

		// Audit endpoints.
		auditHandlers := NewAuditHandlers(cfg.AuditLogger)
		r.Get("/audit", auditHandlers.ListAuditEntries)
	})

	return r
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeProblem writes an RFC 7807 Problem Details response.
func writeProblem(w http.ResponseWriter, status int, problemType, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"type":   problemType,
		"title":  title,
		"status": status,
		"detail": detail,
	})
}
