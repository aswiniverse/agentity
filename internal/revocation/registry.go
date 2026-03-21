package revocation

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// RevocationEntry records a revocation event.
type RevocationEntry struct {
	TokenID   string    `json:"token_id"`
	AgentID   string    `json:"agent_id"`
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
	Cascade   bool      `json:"cascade"`
}

// Registry manages token and agent revocations with Redis (primary) and in-memory (fallback).
type Registry struct {
	redis         *redis.Client
	mu            sync.RWMutex
	tokenRevocations map[string]RevocationEntry
	agentRevocations map[string]RevocationEntry
}

// NewRegistry creates a new revocation registry. If redisClient is nil, it operates in memory-only mode.
func NewRegistry(redisClient *redis.Client) *Registry {
	return &Registry{
		redis:            redisClient,
		tokenRevocations: make(map[string]RevocationEntry),
		agentRevocations: make(map[string]RevocationEntry),
	}
}

// RevokeToken marks a token as revoked.
func (r *Registry) RevokeToken(ctx context.Context, tokenID string, reason string) error {
	entry := RevocationEntry{
		TokenID:   tokenID,
		Reason:    reason,
		RevokedAt: time.Now().UTC(),
	}

	r.mu.Lock()
	r.tokenRevocations[tokenID] = entry
	r.mu.Unlock()

	if r.redis != nil {
		key := fmt.Sprintf("revocation:token:%s", tokenID)
		if err := r.redis.Set(ctx, key, reason, 0).Err(); err != nil {
			return fmt.Errorf("redis set token revocation: %w", err)
		}
	}
	return nil
}

// RevokeAgent marks an agent as revoked. If cascade is true, it is recorded for cascade processing.
func (r *Registry) RevokeAgent(ctx context.Context, agentID string, reason string, cascade bool) error {
	entry := RevocationEntry{
		AgentID:   agentID,
		Reason:    reason,
		RevokedAt: time.Now().UTC(),
		Cascade:   cascade,
	}

	r.mu.Lock()
	r.agentRevocations[agentID] = entry
	r.mu.Unlock()

	if r.redis != nil {
		key := fmt.Sprintf("revocation:agent:%s", agentID)
		if err := r.redis.Set(ctx, key, reason, 0).Err(); err != nil {
			return fmt.Errorf("redis set agent revocation: %w", err)
		}
	}
	return nil
}

// IsTokenRevoked checks if a token has been revoked.
func (r *Registry) IsTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	// Check Redis first if available.
	if r.redis != nil {
		key := fmt.Sprintf("revocation:token:%s", tokenID)
		result, err := r.redis.Exists(ctx, key).Result()
		if err != nil {
			// Fall through to memory check.
		} else {
			return result > 0, nil
		}
	}

	r.mu.RLock()
	_, revoked := r.tokenRevocations[tokenID]
	r.mu.RUnlock()
	return revoked, nil
}

// IsAgentRevoked checks if an agent has been revoked.
func (r *Registry) IsAgentRevoked(ctx context.Context, agentID string) (bool, error) {
	if r.redis != nil {
		key := fmt.Sprintf("revocation:agent:%s", agentID)
		result, err := r.redis.Exists(ctx, key).Result()
		if err != nil {
			// Fall through to memory check.
		} else {
			return result > 0, nil
		}
	}

	r.mu.RLock()
	_, revoked := r.agentRevocations[agentID]
	r.mu.RUnlock()
	return revoked, nil
}

// ListTokenRevocations returns all token revocation entries.
func (r *Registry) ListTokenRevocations() []RevocationEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entries := make([]RevocationEntry, 0, len(r.tokenRevocations))
	for _, e := range r.tokenRevocations {
		entries = append(entries, e)
	}
	return entries
}

// ListAgentRevocations returns all agent revocation entries.
func (r *Registry) ListAgentRevocations() []RevocationEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entries := make([]RevocationEntry, 0, len(r.agentRevocations))
	for _, e := range r.agentRevocations {
		entries = append(entries, e)
	}
	return entries
}

// revocationCheckerAdapter wraps Registry to implement token.RevocationChecker.
type revocationCheckerAdapter struct {
	registry *Registry
	ctx      context.Context
}

// NewRevocationChecker returns a token.RevocationChecker backed by this registry.
func (r *Registry) NewRevocationChecker(ctx context.Context) *revocationCheckerAdapter {
	return &revocationCheckerAdapter{registry: r, ctx: ctx}
}

func (a *revocationCheckerAdapter) IsTokenRevoked(tokenID string) (bool, error) {
	return a.registry.IsTokenRevoked(a.ctx, tokenID)
}

func (a *revocationCheckerAdapter) IsAgentRevoked(agentID string) (bool, error) {
	return a.registry.IsAgentRevoked(a.ctx, agentID)
}
