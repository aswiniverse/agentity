package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ComputeSystemPromptHash returns the hex-encoded SHA256 hash of a system prompt.
func ComputeSystemPromptHash(prompt string) string {
	h := sha256.Sum256([]byte(prompt))
	return hex.EncodeToString(h[:])
}

// ComputeToolFingerprint returns the hex-encoded SHA256 hash of sorted, pipe-joined tool names.
func ComputeToolFingerprint(tools []string) string {
	sorted := make([]string, len(tools))
	copy(sorted, tools)
	sort.Strings(sorted)
	joined := strings.Join(sorted, "|")
	h := sha256.Sum256([]byte(joined))
	return hex.EncodeToString(h[:])
}

// AgentFingerprintInput holds the fields needed to compute an agent fingerprint.
type AgentFingerprintInput struct {
	SystemPromptHash string
	ToolFingerprint  string
	Model            string
}

// ComputeAgentFingerprint returns the hex-encoded SHA256 hash combining
// system prompt hash, tool fingerprint, and model identifier.
func ComputeAgentFingerprint(input AgentFingerprintInput) string {
	data := fmt.Sprintf("%s|%s|%s", input.SystemPromptHash, input.ToolFingerprint, input.Model)
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}
