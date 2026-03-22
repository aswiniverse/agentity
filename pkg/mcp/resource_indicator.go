package mcp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ValidateResourceIndicator checks that the JWT's `aud` claim matches expectedResource.
// Returns nil if valid, error if not.
// Parses the JWT without signature verification (token is already verified by the delegation engine).
func ValidateResourceIndicator(encodedToken string, expectedResource string) error {
	parts := strings.Split(encodedToken, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (middle segment). Base64url without padding.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decode JWT payload: %w", err)
	}

	// Use a raw map to handle aud as string or []string.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return fmt.Errorf("parse JWT payload: %w", err)
	}

	audRaw, ok := raw["aud"]
	if !ok {
		return fmt.Errorf("JWT missing 'aud' claim")
	}

	// Try string first.
	var audStr string
	if err := json.Unmarshal(audRaw, &audStr); err == nil {
		if audStr == expectedResource {
			return nil
		}
		return fmt.Errorf("JWT 'aud' claim %q does not match expected resource %q", audStr, expectedResource)
	}

	// Try []string.
	var audSlice []string
	if err := json.Unmarshal(audRaw, &audSlice); err == nil {
		for _, a := range audSlice {
			if a == expectedResource {
				return nil
			}
		}
		return fmt.Errorf("JWT 'aud' claim %v does not contain expected resource %q", audSlice, expectedResource)
	}

	return fmt.Errorf("JWT 'aud' claim has unexpected format")
}
