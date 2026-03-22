package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresPolicyStore is a PostgreSQL-backed PolicyStore.
type PostgresPolicyStore struct {
	pool *pgxpool.Pool
}

// NewPostgresPolicyStore creates a new PostgresPolicyStore.
func NewPostgresPolicyStore(pool *pgxpool.Pool) *PostgresPolicyStore {
	return &PostgresPolicyStore{pool: pool}
}

// Insert persists a policy to the database.
func (s *PostgresPolicyStore) Insert(p *Policy) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `INSERT INTO policies (id, name, expression, priority, action, created_at)
	          VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := s.pool.Exec(ctx, query,
		p.ID, p.Name, p.Expression, p.Priority, p.Action, p.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert policy: %w", err)
	}
	return nil
}

// Delete removes a policy by ID.
func (s *PostgresPolicyStore) Delete(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tag, err := s.pool.Exec(ctx, "DELETE FROM policies WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("policy %s not found", id)
	}
	return nil
}

// ListAll returns all policies ordered by priority descending.
func (s *PostgresPolicyStore) ListAll() ([]Policy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := s.pool.Query(ctx, `SELECT id, name, expression, priority, action, created_at
	                                FROM policies ORDER BY priority DESC`)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()

	var policies []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.ID, &p.Name, &p.Expression, &p.Priority, &p.Action, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}
