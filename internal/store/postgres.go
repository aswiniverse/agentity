package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/agentity/agentity/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is a PostgreSQL-backed implementation of identity.Store.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates a new PostgreSQL store with connection pooling.
func NewPostgresStore(ctx context.Context, dsn string, maxConns int) (*PostgresStore, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse DSN: %w", err)
	}
	if maxConns > 0 {
		config.MaxConns = int32(maxConns)
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &PostgresStore{pool: pool}, nil
}

// Close closes the connection pool.
func (s *PostgresStore) Close() {
	s.pool.Close()
}

// CreateAgent inserts a new agent into the database.
func (s *PostgresStore) CreateAgent(agent *identity.AgentIdentity) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	toolsJSON, err := json.Marshal(agent.Fingerprint.Tools)
	if err != nil {
		return fmt.Errorf("marshal tools: %w", err)
	}
	metadataJSON, err := json.Marshal(agent.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	query := `INSERT INTO agents (
		id, name, description, version, public_key, key_id,
		system_prompt_hash, tool_fingerprint, tools, model,
		parent_id, status, metadata, created_at, updated_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`

	_, err = s.pool.Exec(ctx, query,
		agent.ID, agent.Name, agent.Description, agent.Version,
		agent.PublicKey, agent.KeyID,
		agent.Fingerprint.SystemPromptHash, agent.Fingerprint.ToolFingerprint,
		string(toolsJSON), agent.Fingerprint.Model,
		nilIfEmpty(agent.ParentID), string(agent.Status),
		string(metadataJSON), agent.CreatedAt, agent.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert agent: %w", err)
	}
	return nil
}

// GetAgent retrieves an agent by ID.
func (s *PostgresStore) GetAgent(id string) (*identity.AgentIdentity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `SELECT id, name, description, version, public_key, key_id,
		system_prompt_hash, tool_fingerprint, tools, model,
		parent_id, status, metadata, created_at, updated_at
	FROM agents WHERE id = $1`

	var agent identity.AgentIdentity
	var toolsJSON, metadataJSON string
	var parentID *string

	err := s.pool.QueryRow(ctx, query, id).Scan(
		&agent.ID, &agent.Name, &agent.Description, &agent.Version,
		&agent.PublicKey, &agent.KeyID,
		&agent.Fingerprint.SystemPromptHash, &agent.Fingerprint.ToolFingerprint,
		&toolsJSON, &agent.Fingerprint.Model,
		&parentID, &agent.Status,
		&metadataJSON, &agent.CreatedAt, &agent.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("query agent: %w", err)
	}

	if parentID != nil {
		agent.ParentID = *parentID
	}

	if err := json.Unmarshal([]byte(toolsJSON), &agent.Fingerprint.Tools); err != nil {
		return nil, fmt.Errorf("unmarshal tools: %w", err)
	}
	if metadataJSON != "" {
		if err := json.Unmarshal([]byte(metadataJSON), &agent.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}

	return &agent, nil
}

// ListAgents returns agents matching the given filter.
func (s *PostgresStore) ListAgents(filter identity.AgentFilter) ([]*identity.AgentIdentity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `SELECT id, name, description, version, public_key, key_id,
		system_prompt_hash, tool_fingerprint, tools, model,
		parent_id, status, metadata, created_at, updated_at
	FROM agents WHERE 1=1`

	var args []interface{}
	argIdx := 1

	if filter.Status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, string(filter.Status))
		argIdx++
	}
	if filter.ParentID != "" {
		query += fmt.Sprintf(" AND parent_id = $%d", argIdx)
		args = append(args, filter.ParentID)
		argIdx++
	}
	if filter.Model != "" {
		query += fmt.Sprintf(" AND model = $%d", argIdx)
		args = append(args, filter.Model)
		argIdx++
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, filter.Offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query agents: %w", err)
	}
	defer rows.Close()

	var agents []*identity.AgentIdentity
	for rows.Next() {
		var agent identity.AgentIdentity
		var toolsJSON, metadataJSON string
		var parentID *string

		if err := rows.Scan(
			&agent.ID, &agent.Name, &agent.Description, &agent.Version,
			&agent.PublicKey, &agent.KeyID,
			&agent.Fingerprint.SystemPromptHash, &agent.Fingerprint.ToolFingerprint,
			&toolsJSON, &agent.Fingerprint.Model,
			&parentID, &agent.Status,
			&metadataJSON, &agent.CreatedAt, &agent.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan agent: %w", err)
		}

		if parentID != nil {
			agent.ParentID = *parentID
		}
		if err := json.Unmarshal([]byte(toolsJSON), &agent.Fingerprint.Tools); err != nil {
			return nil, fmt.Errorf("unmarshal tools: %w", err)
		}
		if metadataJSON != "" {
			if err := json.Unmarshal([]byte(metadataJSON), &agent.Metadata); err != nil {
				return nil, fmt.Errorf("unmarshal metadata: %w", err)
			}
		}
		agents = append(agents, &agent)
	}
	return agents, rows.Err()
}

// UpdateAgent updates an existing agent.
func (s *PostgresStore) UpdateAgent(agent *identity.AgentIdentity) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	toolsJSON, err := json.Marshal(agent.Fingerprint.Tools)
	if err != nil {
		return fmt.Errorf("marshal tools: %w", err)
	}
	metadataJSON, err := json.Marshal(agent.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	query := `UPDATE agents SET
		name = $2, description = $3, version = $4, public_key = $5, key_id = $6,
		system_prompt_hash = $7, tool_fingerprint = $8, tools = $9, model = $10,
		parent_id = $11, status = $12, metadata = $13, updated_at = $14
	WHERE id = $1`

	tag, err := s.pool.Exec(ctx, query,
		agent.ID, agent.Name, agent.Description, agent.Version,
		agent.PublicKey, agent.KeyID,
		agent.Fingerprint.SystemPromptHash, agent.Fingerprint.ToolFingerprint,
		string(toolsJSON), agent.Fingerprint.Model,
		nilIfEmpty(agent.ParentID), string(agent.Status),
		string(metadataJSON), agent.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("update agent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("agent %s not found", agent.ID)
	}
	return nil
}

// DeleteAgent removes an agent by ID.
func (s *PostgresStore) DeleteAgent(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tag, err := s.pool.Exec(ctx, "DELETE FROM agents WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete agent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("agent %s not found", id)
	}
	return nil
}

// GetChildAgents returns all agents whose parent_id matches the given ID.
func (s *PostgresStore) GetChildAgents(parentID string) ([]*identity.AgentIdentity, error) {
	filter := identity.AgentFilter{
		ParentID: parentID,
		Limit:    1000,
	}
	return s.ListAgents(filter)
}

func nilIfEmpty(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}
