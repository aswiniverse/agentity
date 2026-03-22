package user

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerifyOIDCToken(t *testing.T) {
	// Generate RSA key pair for signing test tokens.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	kid := "test-key-1"

	// Set up a mock JWKS endpoint.
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys := jwksKeySet{
			Keys: []jwksKey{
				{
					Kty: "RSA",
					Kid: kid,
					Use: "sig",
					Alg: "RS256",
					N:   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
					E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes()),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(keys)
	}))
	defer jwksServer.Close()

	// Clear the JWKS cache before each test run.
	jwksCache.mu.Lock()
	jwksCache.entries = make(map[string]*jwksCacheEntry)
	jwksCache.mu.Unlock()

	issuer := "https://accounts.example.com"
	clientID := "test-client-id"

	providers := []OIDCProvider{
		{
			ID:        "provider-1",
			IssuerURL: issuer,
			ClientID:  clientID,
			JWKSURL:   jwksServer.URL,
			Enabled:   true,
		},
	}

	t.Run("valid token", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss":   issuer,
			"sub":   "user-123",
			"aud":   clientID,
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
			"iat":   time.Now().Unix(),
			"email": "user@example.com",
			"name":  "Test User",
		})
		token.Header["kid"] = kid

		signedToken, err := token.SignedString(privateKey)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}

		user, err := VerifyOIDCToken(context.Background(), signedToken, providers)
		if err != nil {
			t.Fatalf("verify token: %v", err)
		}

		if user.ExternalID != "user-123" {
			t.Errorf("expected ExternalID=user-123, got %s", user.ExternalID)
		}
		if user.Issuer != issuer {
			t.Errorf("expected Issuer=%s, got %s", issuer, user.Issuer)
		}
		if user.Email != "user@example.com" {
			t.Errorf("expected Email=user@example.com, got %s", user.Email)
		}
		if user.DisplayName != "Test User" {
			t.Errorf("expected DisplayName=Test User, got %s", user.DisplayName)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": issuer,
			"sub": "user-123",
			"aud": clientID,
			"exp": time.Now().Add(-1 * time.Hour).Unix(),
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
		})
		token.Header["kid"] = kid

		signedToken, err := token.SignedString(privateKey)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}

		_, err = VerifyOIDCToken(context.Background(), signedToken, providers)
		if err == nil {
			t.Fatal("expected error for expired token")
		}
	})

	t.Run("wrong audience", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": issuer,
			"sub": "user-123",
			"aud": "wrong-client-id",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
			"iat": time.Now().Unix(),
		})
		token.Header["kid"] = kid

		signedToken, err := token.SignedString(privateKey)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}

		_, err = VerifyOIDCToken(context.Background(), signedToken, providers)
		if err == nil {
			t.Fatal("expected error for wrong audience")
		}
	})

	t.Run("unknown issuer", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": "https://unknown-issuer.com",
			"sub": "user-123",
			"aud": clientID,
			"exp": time.Now().Add(1 * time.Hour).Unix(),
			"iat": time.Now().Unix(),
		})
		token.Header["kid"] = kid

		signedToken, err := token.SignedString(privateKey)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}

		_, err = VerifyOIDCToken(context.Background(), signedToken, providers)
		if err == nil {
			t.Fatal("expected error for unknown issuer")
		}
	})
}
