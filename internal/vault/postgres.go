package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresVaultStore implements VaultStore backed by PostgreSQL.
type PostgresVaultStore struct {
	pool *pgxpool.Pool
}

// NewPostgresVaultStore creates a new PostgreSQL-backed vault store.
func NewPostgresVaultStore(pool *pgxpool.Pool) *PostgresVaultStore {
	return &PostgresVaultStore{pool: pool}
}

func (s *PostgresVaultStore) Put(ctx context.Context, agentID, key, encryptedValue string, iv []byte, keyVersion string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := s.pool.Exec(ctx, `
		INSERT INTO credentials (agent_id, key, encrypted_value, iv, key_version, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (agent_id, key) DO UPDATE SET
			encrypted_value = EXCLUDED.encrypted_value,
			iv = EXCLUDED.iv,
			key_version = EXCLUDED.key_version,
			updated_at = NOW()`,
		agentID, key, []byte(encryptedValue), iv, keyVersion,
	)
	if err != nil {
		return fmt.Errorf("put credential: %w", err)
	}
	return nil
}

func (s *PostgresVaultStore) Get(ctx context.Context, agentID, key string) (string, []byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var encryptedValue []byte
	var iv []byte
	var keyVersion string

	err := s.pool.QueryRow(ctx, `
		SELECT encrypted_value, iv, key_version
		FROM credentials
		WHERE agent_id = $1 AND key = $2`,
		agentID, key,
	).Scan(&encryptedValue, &iv, &keyVersion)
	if err != nil {
		return "", nil, "", fmt.Errorf("credential not found: agent=%s key=%s: %w", agentID, key, err)
	}
	return string(encryptedValue), iv, keyVersion, nil
}

func (s *PostgresVaultStore) Delete(ctx context.Context, agentID, key string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	tag, err := s.pool.Exec(ctx,
		`DELETE FROM credentials WHERE agent_id = $1 AND key = $2`,
		agentID, key,
	)
	if err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("credential not found: agent=%s key=%s", agentID, key)
	}
	return nil
}

func (s *PostgresVaultStore) List(ctx context.Context, agentID string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	rows, err := s.pool.Query(ctx,
		`SELECT key FROM credentials WHERE agent_id = $1 ORDER BY key`,
		agentID,
	)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, fmt.Errorf("scan key: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}
