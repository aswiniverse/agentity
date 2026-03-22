package user

import "time"

// User represents a human user authenticated via an external OIDC provider.
type User struct {
	ID          string
	ExternalID  string
	Issuer      string
	Email       string
	DisplayName string
	Metadata    map[string]interface{}
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// UserAgentBinding represents a binding between a user and an agent,
// granting the agent specific scopes on behalf of the user.
type UserAgentBinding struct {
	ID        string
	UserID    string
	AgentID   string
	Scopes    []string
	CreatedAt time.Time
	RevokedAt *time.Time
}

// OIDCProvider represents a registered external OIDC identity provider.
type OIDCProvider struct {
	ID        string
	IssuerURL string
	ClientID  string
	JWKSURL   string
	Enabled   bool
	CreatedAt time.Time
}
