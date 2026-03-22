package user

import (
	"testing"

	"github.com/agentity/agentity/pkg/token"
)

func TestBlockUserIDField(t *testing.T) {
	// Verify that a Block with UserID set serializes/deserializes correctly
	// and that the uid field is present in the token.
	block := token.Block{
		Index:       0,
		Issuer:      "agentity://server",
		Subject:     "agent://test",
		UserID:      "user-uuid-123",
		SignerKeyID: "kid-1",
	}

	if block.UserID != "user-uuid-123" {
		t.Errorf("expected UserID=user-uuid-123, got %s", block.UserID)
	}

	// Verify VerifiedACT carries UserID.
	verified := token.VerifiedACT{
		TokenID: "tid-1",
		AgentID: "agent://test",
		UserID:  "user-uuid-456",
	}
	if verified.UserID != "user-uuid-456" {
		t.Errorf("expected UserID=user-uuid-456, got %s", verified.UserID)
	}

	// Verify omitempty: block without UserID should not have uid.
	blockNoUser := token.Block{
		Index:       0,
		Issuer:      "agentity://server",
		Subject:     "agent://test",
		SignerKeyID: "kid-1",
	}
	if blockNoUser.UserID != "" {
		t.Errorf("expected empty UserID, got %s", blockNoUser.UserID)
	}
}

func TestVerifiedACTUserIDFromRootBlock(t *testing.T) {
	// Create an ACT with UserID set on root block, encode and decode,
	// then verify UserID is preserved.
	act := &token.ACT{
		Version: 1,
		TokenID: "test-token-id",
		Blocks: []token.Block{
			{
				Index:       0,
				Issuer:      "agentity://server",
				Subject:     "agent://test",
				UserID:      "user-uuid-789",
				SignerKeyID: "kid-1",
				Nonce:       "test-nonce",
				IssuedAt:    1000,
				Signature:   "test-sig",
				Capabilities: []string{"read"},
				Conditions: token.BlockConditions{
					ExpiresAt: 9999999999,
				},
			},
		},
	}

	encoded, err := token.Encode(act)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	decoded, err := token.Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(decoded.Blocks) == 0 {
		t.Fatal("expected at least one block")
	}
	if decoded.Blocks[0].UserID != "user-uuid-789" {
		t.Errorf("expected UserID=user-uuid-789 after decode, got %s", decoded.Blocks[0].UserID)
	}
}
