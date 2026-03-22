package user

import (
	"context"
	"testing"
)

func TestBindingLifecycle(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()

	// Create a user.
	u := &User{
		ExternalID: "ext-user-1",
		Issuer:     "https://example.com",
		Email:      "test@example.com",
	}
	if err := store.CreateUser(ctx, u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if u.ID == "" {
		t.Fatal("expected user ID to be set")
	}

	// Create a binding.
	binding := &UserAgentBinding{
		UserID:  u.ID,
		AgentID: "agent://test-agent",
		Scopes:  []string{"read", "write"},
	}
	if err := store.CreateBinding(ctx, binding); err != nil {
		t.Fatalf("create binding: %v", err)
	}
	if binding.ID == "" {
		t.Fatal("expected binding ID to be set")
	}

	// Get binding.
	got, err := store.GetBinding(ctx, u.ID, "agent://test-agent")
	if err != nil {
		t.Fatalf("get binding: %v", err)
	}
	if got.AgentID != "agent://test-agent" {
		t.Errorf("expected AgentID=agent://test-agent, got %s", got.AgentID)
	}
	if len(got.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(got.Scopes))
	}

	// List bindings.
	bindings, err := store.GetBindingsForUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Errorf("expected 1 binding, got %d", len(bindings))
	}

	// Revoke binding.
	if err := store.RevokeBinding(ctx, u.ID, "agent://test-agent"); err != nil {
		t.Fatalf("revoke binding: %v", err)
	}

	// Verify binding is revoked (GetBinding should fail).
	_, err = store.GetBinding(ctx, u.ID, "agent://test-agent")
	if err == nil {
		t.Fatal("expected error getting revoked binding")
	}

	// List should be empty after revocation.
	bindings, err = store.GetBindingsForUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("list bindings after revoke: %v", err)
	}
	if len(bindings) != 0 {
		t.Errorf("expected 0 bindings after revoke, got %d", len(bindings))
	}
}

func TestUserLookupByExternalID(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()

	u := &User{
		ExternalID:  "ext-user-2",
		Issuer:      "https://idp.example.com",
		Email:       "user2@example.com",
		DisplayName: "User Two",
	}
	if err := store.CreateUser(ctx, u); err != nil {
		t.Fatalf("create user: %v", err)
	}

	got, err := store.GetUserByExternalID(ctx, "ext-user-2", "https://idp.example.com")
	if err != nil {
		t.Fatalf("get user by external ID: %v", err)
	}
	if got.Email != "user2@example.com" {
		t.Errorf("expected email user2@example.com, got %s", got.Email)
	}

	// Non-existent external ID.
	_, err = store.GetUserByExternalID(ctx, "nonexistent", "https://idp.example.com")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestOIDCProviderLifecycle(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()

	provider := &OIDCProvider{
		IssuerURL: "https://accounts.google.com",
		ClientID:  "client-123",
		JWKSURL:   "https://www.googleapis.com/oauth2/v3/certs",
		Enabled:   true,
	}
	if err := store.CreateOIDCProvider(ctx, provider); err != nil {
		t.Fatalf("create provider: %v", err)
	}
	if provider.ID == "" {
		t.Fatal("expected provider ID to be set")
	}

	got, err := store.GetOIDCProvider(ctx, "https://accounts.google.com")
	if err != nil {
		t.Fatalf("get provider: %v", err)
	}
	if got.ClientID != "client-123" {
		t.Errorf("expected ClientID=client-123, got %s", got.ClientID)
	}

	providers, err := store.ListOIDCProviders(ctx)
	if err != nil {
		t.Fatalf("list providers: %v", err)
	}
	if len(providers) != 1 {
		t.Errorf("expected 1 provider, got %d", len(providers))
	}
}
