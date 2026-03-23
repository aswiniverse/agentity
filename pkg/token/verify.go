package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	agcrypto "github.com/agentity/agentity/pkg/crypto"
)

// Verify decodes, validates signatures, checks revocation, and returns the verified token.
func Verify(encoded string, keyResolver KeyResolver, revocationCheck RevocationChecker) (*VerifiedACT, error) {
	act, err := Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode token: %w", err)
	}

	if act.Version != 1 {
		return nil, fmt.Errorf("unsupported token version: %d", act.Version)
	}
	if len(act.Blocks) == 0 {
		return nil, fmt.Errorf("token has no blocks")
	}

	// Check token-level revocation.
	if revocationCheck != nil {
		revoked, err := revocationCheck.IsTokenRevoked(act.TokenID)
		if err != nil {
			return nil, fmt.Errorf("check token revocation: %w", err)
		}
		if revoked {
			return nil, fmt.Errorf("token %s has been revoked", act.TokenID)
		}
	}

	now := time.Now().Unix()
	delegationPath := make([]string, 0, len(act.Blocks))

	for i, block := range act.Blocks {
		// Validate block index.
		if block.Index != i {
			return nil, fmt.Errorf("block %d has wrong index %d", i, block.Index)
		}

		// Check expiry.
		if block.Conditions.ExpiresAt > 0 && block.Conditions.ExpiresAt < now {
			return nil, fmt.Errorf("block %d has expired", i)
		}
		if block.Conditions.ExpiresAt == 0 {
			return nil, fmt.Errorf("block %d: missing expiry (ExpiresAt must be set)", i)
		}

		// Check not-before.
		if block.Conditions.NotBefore > 0 && block.Conditions.NotBefore > now {
			return nil, fmt.Errorf("block %d is not yet valid", i)
		}

		// Check agent revocation.
		if revocationCheck != nil {
			revoked, err := revocationCheck.IsAgentRevoked(block.Subject)
			if err != nil {
				return nil, fmt.Errorf("check agent revocation for %s: %w", block.Subject, err)
			}
			if revoked {
				return nil, fmt.Errorf("agent %s has been revoked", block.Subject)
			}
			if i > 0 {
				revoked, err = revocationCheck.IsAgentRevoked(block.Issuer)
				if err != nil {
					return nil, fmt.Errorf("check issuer revocation for %s: %w", block.Issuer, err)
				}
				if revoked {
					return nil, fmt.Errorf("issuer agent %s has been revoked", block.Issuer)
				}
			}
		}

		// Verify chain linkage: block[i].issuer == block[i-1].subject for i > 0.
		if i > 0 {
			if block.Issuer != act.Blocks[i-1].Subject {
				return nil, fmt.Errorf("block %d issuer %q does not match previous block subject %q", i, block.Issuer, act.Blocks[i-1].Subject)
			}
		}

		// Verify capability subset for delegation blocks.
		if i > 0 {
			parentCaps := effectiveCapabilities(act.Blocks[:i])
			for _, cap := range block.Capabilities {
				if !contains(parentCaps, cap) {
					return nil, fmt.Errorf("block %d capability %q not in parent effective capabilities", i, cap)
				}
			}
		}

		// Verify expiry monotonicity for delegation blocks.
		if i > 0 {
			parentExp := act.Blocks[i-1].Conditions.ExpiresAt
			if parentExp > 0 && block.Conditions.ExpiresAt > parentExp {
				return nil, fmt.Errorf("block %d expiry exceeds parent expiry", i)
			}
		}

		// Resolve the signer's public key and verify signature.
		var pubKey ed25519.PublicKey
		if i == 0 {
			// Root block: resolve from key resolver (server key).
			pubKeyB64, err := keyResolver.ResolveKey(block.SignerKeyID)
			if err != nil {
				return nil, fmt.Errorf("resolve root key %s: %w", block.SignerKeyID, err)
			}
			pubKey, err = agcrypto.DecodePublicKeyBase64(pubKeyB64)
			if err != nil {
				return nil, fmt.Errorf("decode root public key: %w", err)
			}
		} else {
			// Delegation block: resolve from key resolver (agent key).
			pubKeyB64, err := keyResolver.ResolveKey(block.SignerKeyID)
			if err != nil {
				return nil, fmt.Errorf("resolve key %s for block %d: %w", block.SignerKeyID, i, err)
			}
			pubKey, err = agcrypto.DecodePublicKeyBase64(pubKeyB64)
			if err != nil {
				return nil, fmt.Errorf("decode public key for block %d: %w", i, err)
			}
		}

		// Verify signature.
		canonical, err := canonicalBlockBytes(&block)
		if err != nil {
			return nil, fmt.Errorf("canonical bytes for block %d: %w", i, err)
		}
		sigBytes, err := base64.RawURLEncoding.DecodeString(block.Signature)
		if err != nil {
			return nil, fmt.Errorf("decode signature for block %d: %w", i, err)
		}
		if !ed25519.Verify(pubKey, canonical, sigBytes) {
			return nil, fmt.Errorf("invalid signature on block %d", i)
		}

		delegationPath = append(delegationPath, block.Subject)
	}

	// Compute effective capabilities (intersection of all blocks).
	caps := effectiveCapabilities(act.Blocks)

	// The final subject is the last block's subject.
	lastBlock := act.Blocks[len(act.Blocks)-1]

	verified := &VerifiedACT{
		TokenID:        act.TokenID,
		AgentID:        lastBlock.Subject,
		Capabilities:   caps,
		ExpiresAt:      lastBlock.Conditions.ExpiresAt,
		ChainDepth:     len(act.Blocks),
		DelegationPath: delegationPath,
	}

	// Populate UserID from the root block if present.
	if act.Blocks[0].UserID != "" {
		verified.UserID = act.Blocks[0].UserID
	}

	return verified, nil
}
