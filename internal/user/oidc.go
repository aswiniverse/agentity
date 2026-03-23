package user

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// oidcHTTPClient is used for all OIDC/JWKS HTTP requests with a fixed timeout.
var oidcHTTPClient = &http.Client{Timeout: 10 * time.Second}

const jwksCacheMaxSize = 100

// jwksCache caches JWKS key sets with a TTL.
var jwksCache = &jwksCacheStore{
	entries: make(map[string]*jwksCacheEntry),
}

type jwksCacheEntry struct {
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

type jwksCacheStore struct {
	mu      sync.RWMutex
	entries map[string]*jwksCacheEntry
}

const jwksCacheTTL = 1 * time.Hour

// jwksKeySet represents the JSON structure of a JWKS response.
type jwksKeySet struct {
	Keys []jwksKey `json:"keys"`
}

type jwksKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// fetchJWKS fetches and caches JWKS keys from the given URL.
func fetchJWKS(ctx context.Context, jwksURL string) (map[string]*rsa.PublicKey, error) {
	jwksCache.mu.RLock()
	if entry, ok := jwksCache.entries[jwksURL]; ok {
		if time.Since(entry.fetchedAt) < jwksCacheTTL {
			jwksCache.mu.RUnlock()
			return entry.keys, nil
		}
	}
	jwksCache.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create JWKS request: %w", err)
	}

	resp, err := oidcHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS from %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("read JWKS response: %w", err)
	}

	var keySet jwksKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, k := range keySet.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pubKey, err := parseRSAPublicKey(k)
		if err != nil {
			continue // skip invalid keys
		}
		keys[k.Kid] = pubKey
	}

	jwksCache.mu.Lock()
	jwksCache.entries[jwksURL] = &jwksCacheEntry{
		keys:      keys,
		fetchedAt: time.Now(),
	}
	// Evict the oldest entry if cache exceeds the maximum size.
	if len(jwksCache.entries) > jwksCacheMaxSize {
		var oldestURL string
		var oldestTime time.Time
		for u, e := range jwksCache.entries {
			if oldestURL == "" || e.fetchedAt.Before(oldestTime) {
				oldestURL = u
				oldestTime = e.fetchedAt
			}
		}
		delete(jwksCache.entries, oldestURL)
	}
	jwksCache.mu.Unlock()

	return keys, nil
}

func parseRSAPublicKey(k jwksKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode N: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode E: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// VerifyOIDCToken verifies an OIDC ID token against the registered providers.
// It returns a User populated with claims from the token.
func VerifyOIDCToken(ctx context.Context, idToken string, providers []OIDCProvider) (*User, error) {
	// Parse without verification to get the issuer claim.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverified, _, err := parser.ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	claims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	issuer, _ := claims["iss"].(string)
	if issuer == "" {
		return nil, fmt.Errorf("token missing iss claim")
	}

	// Find matching provider.
	var matchedProvider *OIDCProvider
	for i := range providers {
		if providers[i].IssuerURL == issuer && providers[i].Enabled {
			matchedProvider = &providers[i]
			break
		}
	}
	if matchedProvider == nil {
		return nil, fmt.Errorf("no registered OIDC provider for issuer %s", issuer)
	}

	// Fetch JWKS and verify the token.
	keys, err := fetchJWKS(ctx, matchedProvider.JWKSURL)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}

	// Parse and verify the token with signature validation.
	verified, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			// If no kid, try the first available key.
			for _, k := range keys {
				return k, nil
			}
			return nil, fmt.Errorf("no keys available")
		}
		key, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("key %s not found in JWKS", kid)
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(matchedProvider.ClientID),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	verifiedClaims, ok := verified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid verified claims")
	}

	sub, _ := verifiedClaims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("token missing sub claim")
	}

	email, _ := verifiedClaims["email"].(string)
	name, _ := verifiedClaims["name"].(string)

	return &User{
		ExternalID:  sub,
		Issuer:      issuer,
		Email:       email,
		DisplayName: name,
	}, nil
}
