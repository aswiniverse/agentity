package user

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UserStore defines the persistence interface for user and binding operations.
type UserStore interface {
	CreateUser(ctx context.Context, user *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByExternalID(ctx context.Context, externalID, issuer string) (*User, error)
	CreateBinding(ctx context.Context, binding *UserAgentBinding) error
	GetBinding(ctx context.Context, userID, agentID string) (*UserAgentBinding, error)
	RevokeBinding(ctx context.Context, userID, agentID string) error
	GetBindingsForUser(ctx context.Context, userID string) ([]UserAgentBinding, error)
	CreateOIDCProvider(ctx context.Context, provider *OIDCProvider) error
	GetOIDCProvider(ctx context.Context, issuerURL string) (*OIDCProvider, error)
	ListOIDCProviders(ctx context.Context) ([]OIDCProvider, error)
}

// PostgresUserStore implements UserStore backed by PostgreSQL.
type PostgresUserStore struct {
	pool *pgxpool.Pool
}

// NewPostgresUserStore creates a new PostgreSQL-backed user store.
func NewPostgresUserStore(pool *pgxpool.Pool) *PostgresUserStore {
	return &PostgresUserStore{pool: pool}
}

func (s *PostgresUserStore) CreateUser(ctx context.Context, user *User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	metadataJSON, err := json.Marshal(user.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	_, err = s.pool.Exec(ctx,
		`INSERT INTO users (id, external_id, issuer, email, display_name, metadata, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		user.ID, user.ExternalID, user.Issuer, user.Email, user.DisplayName,
		string(metadataJSON), user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (s *PostgresUserStore) GetUser(ctx context.Context, id string) (*User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, external_id, issuer, email, display_name, metadata, created_at, updated_at
		 FROM users WHERE id = $1`, id)
	return scanUser(row)
}

func (s *PostgresUserStore) GetUserByExternalID(ctx context.Context, externalID, issuer string) (*User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, external_id, issuer, email, display_name, metadata, created_at, updated_at
		 FROM users WHERE external_id = $1 AND issuer = $2`, externalID, issuer)
	return scanUser(row)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (*User, error) {
	var u User
	var metadataJSON *string
	var email, displayName *string
	err := row.Scan(&u.ID, &u.ExternalID, &u.Issuer, &email, &displayName, &metadataJSON, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	if email != nil {
		u.Email = *email
	}
	if displayName != nil {
		u.DisplayName = *displayName
	}
	if metadataJSON != nil && *metadataJSON != "" && *metadataJSON != "null" {
		if err := json.Unmarshal([]byte(*metadataJSON), &u.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &u, nil
}

func (s *PostgresUserStore) CreateBinding(ctx context.Context, binding *UserAgentBinding) error {
	if binding.ID == "" {
		binding.ID = uuid.New().String()
	}
	binding.CreatedAt = time.Now()

	scopesJSON, err := json.Marshal(binding.Scopes)
	if err != nil {
		return fmt.Errorf("marshal scopes: %w", err)
	}

	_, err = s.pool.Exec(ctx,
		`INSERT INTO user_agent_bindings (id, user_id, agent_id, scopes, created_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (user_id, agent_id) DO UPDATE SET scopes = $4, revoked_at = NULL`,
		binding.ID, binding.UserID, binding.AgentID, string(scopesJSON), binding.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert binding: %w", err)
	}
	return nil
}

func (s *PostgresUserStore) GetBinding(ctx context.Context, userID, agentID string) (*UserAgentBinding, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, user_id, agent_id, scopes, created_at, revoked_at
		 FROM user_agent_bindings WHERE user_id = $1 AND agent_id = $2 AND revoked_at IS NULL`, userID, agentID)
	return scanBinding(row)
}

func scanBinding(row rowScanner) (*UserAgentBinding, error) {
	var b UserAgentBinding
	var scopesJSON string
	err := row.Scan(&b.ID, &b.UserID, &b.AgentID, &scopesJSON, &b.CreatedAt, &b.RevokedAt)
	if err != nil {
		return nil, fmt.Errorf("scan binding: %w", err)
	}
	if err := json.Unmarshal([]byte(scopesJSON), &b.Scopes); err != nil {
		return nil, fmt.Errorf("unmarshal scopes: %w", err)
	}
	return &b, nil
}

func (s *PostgresUserStore) RevokeBinding(ctx context.Context, userID, agentID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE user_agent_bindings SET revoked_at = NOW() WHERE user_id = $1 AND agent_id = $2 AND revoked_at IS NULL`,
		userID, agentID,
	)
	if err != nil {
		return fmt.Errorf("revoke binding: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("binding not found for user %s and agent %s", userID, agentID)
	}
	return nil
}

func (s *PostgresUserStore) GetBindingsForUser(ctx context.Context, userID string) ([]UserAgentBinding, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, agent_id, scopes, created_at, revoked_at
		 FROM user_agent_bindings WHERE user_id = $1 AND revoked_at IS NULL
		 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("query bindings: %w", err)
	}
	defer rows.Close()

	var bindings []UserAgentBinding
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, *b)
	}
	return bindings, rows.Err()
}

func (s *PostgresUserStore) CreateOIDCProvider(ctx context.Context, provider *OIDCProvider) error {
	if provider.ID == "" {
		provider.ID = uuid.New().String()
	}
	provider.CreatedAt = time.Now()

	_, err := s.pool.Exec(ctx,
		`INSERT INTO oidc_providers (id, issuer_url, client_id, jwks_url, enabled, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		provider.ID, provider.IssuerURL, provider.ClientID, provider.JWKSURL, provider.Enabled, provider.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert oidc provider: %w", err)
	}
	return nil
}

func (s *PostgresUserStore) GetOIDCProvider(ctx context.Context, issuerURL string) (*OIDCProvider, error) {
	var p OIDCProvider
	err := s.pool.QueryRow(ctx,
		`SELECT id, issuer_url, client_id, jwks_url, enabled, created_at
		 FROM oidc_providers WHERE issuer_url = $1`, issuerURL).
		Scan(&p.ID, &p.IssuerURL, &p.ClientID, &p.JWKSURL, &p.Enabled, &p.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get oidc provider: %w", err)
	}
	return &p, nil
}

func (s *PostgresUserStore) ListOIDCProviders(ctx context.Context) ([]OIDCProvider, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, issuer_url, client_id, jwks_url, enabled, created_at
		 FROM oidc_providers WHERE enabled = TRUE ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("query oidc providers: %w", err)
	}
	defer rows.Close()

	var providers []OIDCProvider
	for rows.Next() {
		var p OIDCProvider
		if err := rows.Scan(&p.ID, &p.IssuerURL, &p.ClientID, &p.JWKSURL, &p.Enabled, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan oidc provider: %w", err)
		}
		providers = append(providers, p)
	}
	return providers, rows.Err()
}

// MemoryUserStore implements UserStore with in-memory storage for dev/test.
type MemoryUserStore struct {
	mu        sync.RWMutex
	users     map[string]*User
	bindings  map[string]*UserAgentBinding
	providers map[string]*OIDCProvider
}

// NewMemoryUserStore creates a new in-memory user store.
func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		users:     make(map[string]*User),
		bindings:  make(map[string]*UserAgentBinding),
		providers: make(map[string]*OIDCProvider),
	}
}

func (s *MemoryUserStore) CreateUser(_ context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now
	s.users[user.ID] = user
	return nil
}

func (s *MemoryUserStore) GetUser(_ context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, fmt.Errorf("user %s not found", id)
	}
	return u, nil
}

func (s *MemoryUserStore) GetUserByExternalID(_ context.Context, externalID, issuer string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.ExternalID == externalID && u.Issuer == issuer {
			return u, nil
		}
	}
	return nil, fmt.Errorf("user with external_id %s and issuer %s not found", externalID, issuer)
}

func (s *MemoryUserStore) CreateBinding(_ context.Context, binding *UserAgentBinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if binding.ID == "" {
		binding.ID = uuid.New().String()
	}
	binding.CreatedAt = time.Now()
	key := binding.UserID + ":" + binding.AgentID
	s.bindings[key] = binding
	return nil
}

func (s *MemoryUserStore) GetBinding(_ context.Context, userID, agentID string) (*UserAgentBinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := userID + ":" + agentID
	b, ok := s.bindings[key]
	if !ok || b.RevokedAt != nil {
		return nil, fmt.Errorf("binding not found for user %s and agent %s", userID, agentID)
	}
	return b, nil
}

func (s *MemoryUserStore) RevokeBinding(_ context.Context, userID, agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := userID + ":" + agentID
	b, ok := s.bindings[key]
	if !ok || b.RevokedAt != nil {
		return fmt.Errorf("binding not found for user %s and agent %s", userID, agentID)
	}
	now := time.Now()
	b.RevokedAt = &now
	return nil
}

func (s *MemoryUserStore) GetBindingsForUser(_ context.Context, userID string) ([]UserAgentBinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []UserAgentBinding
	for _, b := range s.bindings {
		if b.UserID == userID && b.RevokedAt == nil {
			result = append(result, *b)
		}
	}
	return result, nil
}

func (s *MemoryUserStore) CreateOIDCProvider(_ context.Context, provider *OIDCProvider) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if provider.ID == "" {
		provider.ID = uuid.New().String()
	}
	provider.CreatedAt = time.Now()
	s.providers[provider.IssuerURL] = provider
	return nil
}

func (s *MemoryUserStore) GetOIDCProvider(_ context.Context, issuerURL string) (*OIDCProvider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.providers[issuerURL]
	if !ok {
		return nil, fmt.Errorf("oidc provider %s not found", issuerURL)
	}
	return p, nil
}

func (s *MemoryUserStore) ListOIDCProviders(_ context.Context) ([]OIDCProvider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []OIDCProvider
	for _, p := range s.providers {
		if p.Enabled {
			result = append(result, *p)
		}
	}
	return result, nil
}
