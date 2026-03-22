package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresAuditStore is a PostgreSQL-backed implementation of AuditStore.
type PostgresAuditStore struct {
	pool *pgxpool.Pool
}

// NewPostgresAuditStore creates a new PostgresAuditStore using an existing pool.
func NewPostgresAuditStore(pool *pgxpool.Pool) *PostgresAuditStore {
	return &PostgresAuditStore{pool: pool}
}

// Insert persists an audit entry into the database.
func (s *PostgresAuditStore) Insert(entry *AuditEntry) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	metadataJSON, err := json.Marshal(entry.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO audit_log
			(id, event_type, actor_id, target_id, action, token_id, outcome, reason, metadata, timestamp, signature)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`,
		entry.ID,
		string(entry.Type),
		entry.ActorID,
		entry.TargetID,
		entry.Action,
		nilIfEmpty(entry.TokenID),
		entry.Outcome,
		entry.Reason,
		string(metadataJSON),
		entry.Timestamp,
		entry.Signature,
	)
	if err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}
	return nil
}

// List retrieves audit entries matching the given filter ordered by timestamp DESC.
func (s *PostgresAuditStore) List(filter AuditFilter) ([]AuditEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `SELECT id, event_type, actor_id, target_id, action, token_id, outcome, reason, metadata, timestamp, signature
		FROM audit_log WHERE 1=1`

	var args []interface{}
	argIdx := 1

	if filter.ActorID != "" {
		query += fmt.Sprintf(" AND actor_id = $%d", argIdx)
		args = append(args, filter.ActorID)
		argIdx++
	}
	if filter.TargetID != "" {
		query += fmt.Sprintf(" AND target_id = $%d", argIdx)
		args = append(args, filter.TargetID)
		argIdx++
	}
	if filter.Type != "" {
		query += fmt.Sprintf(" AND event_type = $%d", argIdx)
		args = append(args, filter.Type)
		argIdx++
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, filter.Offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var eventType string
		var tokenID *string
		var metadataJSON string

		err := rows.Scan(
			&e.ID, &eventType, &e.ActorID, &e.TargetID, &e.Action,
			&tokenID, &e.Outcome, &e.Reason, &metadataJSON, &e.Timestamp, &e.Signature,
		)
		if err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}

		e.Type = AuditEventType(eventType)
		if tokenID != nil {
			e.TokenID = *tokenID
		}
		if metadataJSON != "" && metadataJSON != "null" && metadataJSON != "{}" {
			if err := json.Unmarshal([]byte(metadataJSON), &e.Metadata); err != nil {
				return nil, fmt.Errorf("unmarshal metadata: %w", err)
			}
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Count returns the total number of audit log entries.
func (s *PostgresAuditStore) Count() (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var count int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count audit entries: %w", err)
	}
	return count, nil
}

// nilIfEmpty returns nil for an empty string, used for nullable TEXT columns.
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
