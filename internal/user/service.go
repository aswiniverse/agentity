package user

import (
	"context"
	"errors"
	"fmt"
)

// UserService provides business logic for user-agent binding operations.
type UserService struct {
	store UserStore
}

// NewUserService creates a new UserService.
func NewUserService(store UserStore) *UserService {
	return &UserService{store: store}
}

// Store returns the underlying UserStore for direct access when needed.
func (s *UserService) Store() UserStore {
	return s.store
}

// BindUserToAgent verifies the OIDC token, upserts the user, and creates a binding.
func (s *UserService) BindUserToAgent(ctx context.Context, oidcToken, agentID string, scopes []string) (*UserAgentBinding, error) {
	// Get providers.
	providers, err := s.store.ListOIDCProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("list OIDC providers: %w", err)
	}
	if len(providers) == 0 {
		return nil, fmt.Errorf("no OIDC providers configured")
	}

	// Verify the OIDC token.
	oidcUser, err := VerifyOIDCToken(ctx, oidcToken, providers)
	if err != nil {
		return nil, fmt.Errorf("verify OIDC token: %w", err)
	}

	// Upsert user: look up by external ID, create if not found.
	existingUser, err := s.store.GetUserByExternalID(ctx, oidcUser.ExternalID, oidcUser.Issuer)
	if err != nil {
		// User doesn't exist, create one.
		if errors.Is(err, ErrNotFound) {
			if err := s.store.CreateUser(ctx, oidcUser); err != nil {
				return nil, fmt.Errorf("create user: %w", err)
			}
			existingUser = oidcUser
		} else {
			return nil, fmt.Errorf("get user: %w", err)
		}
	}

	// Create binding.
	binding := &UserAgentBinding{
		UserID:  existingUser.ID,
		AgentID: agentID,
		Scopes:  scopes,
	}
	if err := s.store.CreateBinding(ctx, binding); err != nil {
		return nil, fmt.Errorf("create binding: %w", err)
	}

	return binding, nil
}

// RevokeBinding revokes a user-agent binding.
func (s *UserService) RevokeBinding(ctx context.Context, userID, agentID string) error {
	return s.store.RevokeBinding(ctx, userID, agentID)
}

// ListUserAgents returns all active bindings for a user.
func (s *UserService) ListUserAgents(ctx context.Context, userID string) ([]UserAgentBinding, error) {
	return s.store.GetBindingsForUser(ctx, userID)
}

// VerifyUserToken verifies an OIDC token using registered providers.
func (s *UserService) VerifyUserToken(ctx context.Context, idToken string) (*User, error) {
	providers, err := s.store.ListOIDCProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("list OIDC providers: %w", err)
	}
	return VerifyOIDCToken(ctx, idToken, providers)
}
