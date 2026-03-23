package audit

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// maxEntries caps the in-memory audit log to prevent unbounded memory growth.
// When the cap is reached, the oldest 10% of entries are dropped.
const maxEntries = 10_000

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
	mu              sync.RWMutex
	entries         []AuditEntry
	signingKey      ed25519.PrivateKey
	store           AuditStore
	persistFailures uint64 // incremented atomically when all retries are exhausted
}

// PersistFailures returns the number of audit entries that could not be persisted
// to the durable store after all retries were exhausted.
func (l *Logger) PersistFailures() uint64 {
	return atomic.LoadUint64(&l.persistFailures)
}

// NewLogger creates a new audit logger with the given signing key.
// store may be nil, in which case only in-memory logging is used.
func NewLogger(signingKey ed25519.PrivateKey, store AuditStore) *Logger {
	return &Logger{
		entries:    make([]AuditEntry, 0, 256),
		signingKey: signingKey,
		store:      store,
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
	return l.append(entry)
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
	return l.append(entry)
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
	return l.append(entry)
}

func (l *Logger) append(entry AuditEntry) (*AuditEntry, error) {
	sig, err := l.signEntry(&entry)
	if err != nil {
		return nil, fmt.Errorf("sign audit entry: %w", err)
	}
	entry.Signature = sig

	l.mu.Lock()
	// Evict oldest 10% when cap is reached to prevent unbounded growth.
	if len(l.entries) >= maxEntries {
		evictCount := maxEntries / 10
		l.entries = l.entries[evictCount:]
		log.Printf("WARN audit: in-memory buffer full, evicting %d oldest entries", evictCount)
	}
	l.entries = append(l.entries, entry)
	l.mu.Unlock()

	// Write-through to persistent store with retry (max 3 attempts).
	if l.store != nil {
		go func(e AuditEntry) {
			const maxRetries = 3
			var lastErr error
			for attempt := 1; attempt <= maxRetries; attempt++ {
				if err := l.store.Insert(&e); err == nil {
					return
				} else {
					lastErr = err
					if attempt < maxRetries {
						time.Sleep(100 * time.Millisecond)
					}
				}
			}
			atomic.AddUint64(&l.persistFailures, 1)
			log.Printf("WARN audit: failed to persist entry %s after 3 retries: %v", e.ID, lastErr)
		}(entry)
	}

	return &entry, nil
}

// List returns audit entries matching the given filter.
// When a persistent store is configured it queries from Postgres;
// on failure (or when no store is configured) it falls back to in-memory.
func (l *Logger) List(filter AuditFilter) []AuditEntry {
	if l.store != nil {
		entries, err := l.store.List(filter)
		if err == nil {
			return entries
		}
		log.Printf("audit: store List failed, falling back to in-memory: %v", err)
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

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
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

func (l *Logger) signEntry(entry *AuditEntry) (string, error) {
	toSign := *entry
	toSign.Signature = ""
	data, err := json.Marshal(toSign)
	if err != nil {
		return "", fmt.Errorf("marshal entry for signing: %w", err)
	}
	sig := ed25519.Sign(l.signingKey, data)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}
