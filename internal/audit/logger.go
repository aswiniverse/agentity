package audit

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AuditEventType classifies audit events.
type AuditEventType string

const (
	EventAgentRegistered AuditEventType = "agent.registered"
	EventTokenIssued     AuditEventType = "token.issued"
	EventTokenDelegated  AuditEventType = "token.delegated"
	EventTokenVerified   AuditEventType = "token.verified"
	EventTokenRevoked    AuditEventType = "token.revoked"
	EventAgentRevoked    AuditEventType = "agent.revoked"
	EventPolicyEvaluated AuditEventType = "policy.evaluated"
	EventAccessDenied    AuditEventType = "access.denied"
)

// AuditEntry represents a single signed audit log entry.
type AuditEntry struct {
	ID        string                 `json:"id"`
	Type      AuditEventType         `json:"type"`
	ActorID   string                 `json:"actor_id"`
	TargetID  string                 `json:"target_id"`
	Action    string                 `json:"action"`
	TokenID   string                 `json:"token_id,omitempty"`
	Outcome   string                 `json:"outcome"`
	Reason    string                 `json:"reason,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Signature string                 `json:"signature"`
}

// AuditFilter is used to query audit entries.
type AuditFilter struct {
	ActorID  string `json:"actor_id,omitempty"`
	TargetID string `json:"target_id,omitempty"`
	Type     string `json:"type,omitempty"`
	Limit    int    `json:"limit,omitempty"`
	Offset   int    `json:"offset,omitempty"`
}

// Logger records and signs audit entries.
type Logger struct {
	mu         sync.Mutex
	entries    []AuditEntry
	signingKey ed25519.PrivateKey
}

// NewLogger creates a new audit logger with the given signing key.
func NewLogger(signingKey ed25519.PrivateKey) *Logger {
	return &Logger{
		entries:    make([]AuditEntry, 0),
		signingKey: signingKey,
	}
}

// Log records a new audit entry, signing it with the server key.
func (l *Logger) Log(eventType AuditEventType, actorID, targetID, action, outcome string, metadata map[string]interface{}) (*AuditEntry, error) {
	entry := AuditEntry{
		ID:        uuid.New().String(),
		Type:      eventType,
		ActorID:   actorID,
		TargetID:  targetID,
		Action:    action,
		Outcome:   outcome,
		Metadata:  metadata,
		Timestamp: time.Now().UTC(),
	}

	sig, err := l.signEntry(&entry)
	if err != nil {
		return nil, fmt.Errorf("sign audit entry: %w", err)
	}
	entry.Signature = sig

	l.mu.Lock()
	l.entries = append(l.entries, entry)
	l.mu.Unlock()

	return &entry, nil
}

// LogWithToken records an audit entry that references a specific token.
func (l *Logger) LogWithToken(eventType AuditEventType, actorID, targetID, action, tokenID, outcome string, metadata map[string]interface{}) (*AuditEntry, error) {
	entry := AuditEntry{
		ID:        uuid.New().String(),
		Type:      eventType,
		ActorID:   actorID,
		TargetID:  targetID,
		Action:    action,
		TokenID:   tokenID,
		Outcome:   outcome,
		Metadata:  metadata,
		Timestamp: time.Now().UTC(),
	}

	sig, err := l.signEntry(&entry)
	if err != nil {
		return nil, fmt.Errorf("sign audit entry: %w", err)
	}
	entry.Signature = sig

	l.mu.Lock()
	l.entries = append(l.entries, entry)
	l.mu.Unlock()

	return &entry, nil
}

// LogDenied records an access denied event with a reason.
func (l *Logger) LogDenied(actorID, targetID, action, reason string, metadata map[string]interface{}) (*AuditEntry, error) {
	entry := AuditEntry{
		ID:        uuid.New().String(),
		Type:      EventAccessDenied,
		ActorID:   actorID,
		TargetID:  targetID,
		Action:    action,
		Outcome:   "denied",
		Reason:    reason,
		Metadata:  metadata,
		Timestamp: time.Now().UTC(),
	}

	sig, err := l.signEntry(&entry)
	if err != nil {
		return nil, fmt.Errorf("sign audit entry: %w", err)
	}
	entry.Signature = sig

	l.mu.Lock()
	l.entries = append(l.entries, entry)
	l.mu.Unlock()

	return &entry, nil
}

// List returns audit entries matching the given filter.
func (l *Logger) List(filter AuditFilter) []AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > 200 {
		filter.Limit = 200
	}

	var filtered []AuditEntry
	for _, e := range l.entries {
		if filter.ActorID != "" && e.ActorID != filter.ActorID {
			continue
		}
		if filter.TargetID != "" && e.TargetID != filter.TargetID {
			continue
		}
		if filter.Type != "" && string(e.Type) != filter.Type {
			continue
		}
		filtered = append(filtered, e)
	}

	// Apply offset and limit.
	if filter.Offset >= len(filtered) {
		return nil
	}
	filtered = filtered[filter.Offset:]
	if len(filtered) > filter.Limit {
		filtered = filtered[:filter.Limit]
	}
	return filtered
}

// Count returns the total number of audit entries.
func (l *Logger) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

func (l *Logger) signEntry(entry *AuditEntry) (string, error) {
	// Create a copy without signature for signing.
	toSign := *entry
	toSign.Signature = ""
	data, err := json.Marshal(toSign)
	if err != nil {
		return "", fmt.Errorf("marshal entry for signing: %w", err)
	}
	sig := ed25519.Sign(l.signingKey, data)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}
