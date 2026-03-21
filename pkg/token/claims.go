package token

// BlockConditions defines the conditions and constraints for a token block.
type BlockConditions struct {
	ExpiresAt       int64             `json:"exp"`
	NotBefore       int64             `json:"nbf,omitempty"`
	MaxDelegations  int               `json:"max_deleg,omitempty"`
	AllowedModels   []string          `json:"models,omitempty"`
	RequiredClaims  map[string]string `json:"req_claims,omitempty"`
	MaxCallsPerTool map[string]int    `json:"max_calls,omitempty"`
}

// ACT is the AgentCapability Token - the core token format.
type ACT struct {
	Version int     `json:"v"`
	TokenID string  `json:"tid"`
	Blocks  []Block `json:"blocks"`
}

// Block represents a single block in the delegation chain.
type Block struct {
	Index        int             `json:"idx"`
	Issuer       string          `json:"iss"`
	Subject      string          `json:"sub"`
	Capabilities []string        `json:"caps"`
	Conditions   BlockConditions `json:"cond"`
	Nonce        string          `json:"nonce"`
	IssuedAt     int64           `json:"iat"`
	Signature    string          `json:"sig"`
	SignerKeyID  string          `json:"kid"`
}

// VerifiedACT represents a successfully verified ACT token with resolved fields.
type VerifiedACT struct {
	TokenID        string   `json:"token_id"`
	AgentID        string   `json:"agent_id"`
	Capabilities   []string `json:"capabilities"`
	ExpiresAt      int64    `json:"expires_at"`
	ChainDepth     int      `json:"chain_depth"`
	DelegationPath []string `json:"delegation_path"`
}

// KeyResolver resolves a signer key ID to a public key (base64url-encoded).
type KeyResolver interface {
	ResolveKey(keyID string) (publicKeyBase64 string, err error)
}

// RevocationChecker checks whether a token or agent has been revoked.
type RevocationChecker interface {
	IsTokenRevoked(tokenID string) (bool, error)
	IsAgentRevoked(agentID string) (bool, error)
}
