package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	agcrypto "github.com/agentity/agentity/pkg/crypto"
	"github.com/google/uuid"
)

// IssueRootToken creates a new ACT with a single root block signed by the server's root key.
func IssueRootToken(agentID string, capabilities []string, conditions BlockConditions, rootKey ed25519.PrivateKey) (*ACT, error) {
	if len(capabilities) == 0 {
		return nil, fmt.Errorf("capabilities must not be empty")
	}
	if conditions.ExpiresAt == 0 {
		return nil, fmt.Errorf("expiry (exp) must be set")
	}
	if conditions.ExpiresAt <= time.Now().Unix() {
		return nil, fmt.Errorf("expiry must be in the future")
	}

	nonce, err := generateNonce()
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	pub := rootKey.Public().(ed25519.PublicKey)
	kid := agcrypto.ComputeKeyID(pub)
	serverID := "agentity://server"

	block := Block{
		Index:        0,
		Issuer:       serverID,
		Subject:      agentID,
		Capabilities: sortedCopy(capabilities),
		Conditions:   conditions,
		Nonce:        nonce,
		IssuedAt:     time.Now().Unix(),
		SignerKeyID:  kid,
	}

	sig, err := signBlock(&block, rootKey)
	if err != nil {
		return nil, fmt.Errorf("sign root block: %w", err)
	}
	block.Signature = sig

	act := &ACT{
		Version: 1,
		TokenID: uuid.New().String(),
		Blocks:  []Block{block},
	}
	return act, nil
}

// Delegate creates a new ACT by appending a delegation block to the parent token.
// It enforces capability subset, expiry monotonicity, and max delegation depth.
func Delegate(parent *ACT, childAgentID string, capabilities []string, conditions BlockConditions, parentAgentKey ed25519.PrivateKey) (*ACT, error) {
	if parent == nil || len(parent.Blocks) == 0 {
		return nil, fmt.Errorf("parent token is invalid")
	}
	if len(capabilities) == 0 {
		return nil, fmt.Errorf("capabilities must not be empty")
	}

	// Compute effective capabilities of the parent (intersection of all blocks).
	parentCaps := effectiveCapabilities(parent.Blocks)

	// Validate capability subset: every requested capability must exist in parent's effective set.
	for _, cap := range capabilities {
		if !contains(parentCaps, cap) {
			return nil, fmt.Errorf("capability amplification denied: %q not in parent effective capabilities", cap)
		}
	}

	// Validate expiry monotonicity.
	lastBlock := parent.Blocks[len(parent.Blocks)-1]
	if conditions.ExpiresAt == 0 {
		return nil, fmt.Errorf("expiry (exp) must be set")
	}
	if conditions.ExpiresAt > lastBlock.Conditions.ExpiresAt {
		return nil, fmt.Errorf("delegation expiry (%d) must be <= parent expiry (%d)", conditions.ExpiresAt, lastBlock.Conditions.ExpiresAt)
	}

	// Validate max delegations.
	if lastBlock.Conditions.MaxDelegations > 0 {
		currentDepth := len(parent.Blocks) // number of blocks already present
		if currentDepth >= lastBlock.Conditions.MaxDelegations+1 {
			return nil, fmt.Errorf("max delegation depth reached: %d", lastBlock.Conditions.MaxDelegations)
		}
	}
	// Also check root block's max delegations.
	rootBlock := parent.Blocks[0]
	if rootBlock.Conditions.MaxDelegations > 0 {
		currentDepth := len(parent.Blocks)
		if currentDepth >= rootBlock.Conditions.MaxDelegations+1 {
			return nil, fmt.Errorf("max delegation depth reached (root limit): %d", rootBlock.Conditions.MaxDelegations)
		}
	}

	nonce, err := generateNonce()
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	pub := parentAgentKey.Public().(ed25519.PublicKey)
	kid := agcrypto.ComputeKeyID(pub)

	// The issuer is the subject of the last block (the parent agent).
	issuer := lastBlock.Subject

	newBlock := Block{
		Index:        len(parent.Blocks),
		Issuer:       issuer,
		Subject:      childAgentID,
		Capabilities: sortedCopy(capabilities),
		Conditions:   conditions,
		Nonce:        nonce,
		IssuedAt:     time.Now().Unix(),
		SignerKeyID:  kid,
	}

	sig, err := signBlock(&newBlock, parentAgentKey)
	if err != nil {
		return nil, fmt.Errorf("sign delegation block: %w", err)
	}
	newBlock.Signature = sig

	// Create a new ACT with all parent blocks plus the new one.
	newBlocks := make([]Block, len(parent.Blocks)+1)
	copy(newBlocks, parent.Blocks)
	newBlocks[len(parent.Blocks)] = newBlock

	act := &ACT{
		Version: parent.Version,
		TokenID: parent.TokenID,
		Blocks:  newBlocks,
	}
	return act, nil
}

// Encode serializes an ACT to a base64url-encoded JSON string.
func Encode(act *ACT) (string, error) {
	data, err := json.Marshal(act)
	if err != nil {
		return "", fmt.Errorf("marshal ACT: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// Decode deserializes a base64url-encoded JSON string to an ACT.
func Decode(encoded string) (*ACT, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	var act ACT
	if err := json.Unmarshal(data, &act); err != nil {
		return nil, fmt.Errorf("unmarshal ACT: %w", err)
	}
	return &act, nil
}

// signBlock creates an Ed25519 signature over the canonical form of the block.
func signBlock(block *Block, key ed25519.PrivateKey) (string, error) {
	canonical, err := canonicalBlockBytes(block)
	if err != nil {
		return "", fmt.Errorf("canonical block bytes: %w", err)
	}
	sig := ed25519.Sign(key, canonical)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// canonicalBlockBytes produces the canonical JSON representation of a block
// for signing. The signature field is excluded.
func canonicalBlockBytes(block *Block) ([]byte, error) {
	// Create a map with sorted keys, excluding the signature.
	m := map[string]interface{}{
		"idx":   block.Index,
		"iss":   block.Issuer,
		"sub":   block.Subject,
		"caps":  block.Capabilities,
		"cond":  block.Conditions,
		"nonce": block.Nonce,
		"iat":   block.IssuedAt,
		"kid":   block.SignerKeyID,
	}
	if block.UserID != "" {
		m["uid"] = block.UserID
	}
	return canonicalJSON(m)
}

// canonicalJSON produces a deterministic JSON encoding with sorted keys.
func canonicalJSON(v interface{}) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	// Re-parse and re-marshal through an ordered structure.
	// json.Marshal already sorts map keys in Go, so this is canonical.
	return data, nil
}

// effectiveCapabilities computes the intersection of capabilities across all blocks.
func effectiveCapabilities(blocks []Block) []string {
	if len(blocks) == 0 {
		return nil
	}
	caps := make(map[string]bool)
	for _, c := range blocks[0].Capabilities {
		caps[c] = true
	}
	for i := 1; i < len(blocks); i++ {
		blockCaps := make(map[string]bool)
		for _, c := range blocks[i].Capabilities {
			blockCaps[c] = true
		}
		for c := range caps {
			if !blockCaps[c] {
				delete(caps, c)
			}
		}
	}
	result := make([]string, 0, len(caps))
	for c := range caps {
		result = append(result, c)
	}
	sort.Strings(result)
	return result
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func sortedCopy(s []string) []string {
	c := make([]string, len(s))
	copy(c, s)
	sort.Strings(c)
	return c
}

func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
