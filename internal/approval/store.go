package approval

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ApprovalStore defines the persistence interface for approval requests.
type ApprovalStore interface {
	Create(ctx context.Context, req *ApprovalRequest) error
	Get(ctx context.Context, id string) (*ApprovalRequest, error)
	Approve(ctx context.Context, id, approverID string) error
	Deny(ctx context.Context, id, approverID string) error
	ListPending(ctx context.Context, agentID string) ([]ApprovalRequest, error)
}

// PostgresApprovalStore implements ApprovalStore backed by PostgreSQL.
type PostgresApprovalStore struct {
	pool *pgxpool.Pool
}

// NewPostgresApprovalStore creates a new PostgreSQL-backed approval store.
func NewPostgresApprovalStore(pool *pgxpool.Pool) *PostgresApprovalStore {
	return &PostgresApprovalStore{pool: pool}
}

func (s *PostgresApprovalStore) Create(ctx context.Context, req *ApprovalRequest) error {
	if req.ID == "" {
		req.ID = uuid.New().String()
	}
	req.CreatedAt = time.Now()
	req.Status = StatusPending

	metadataJSON, err := json.Marshal(req.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	_, err = s.pool.Exec(ctx,
		`INSERT INTO approval_requests (id, agent_id, token_id, resource, reason, status, webhook_url, metadata, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		req.ID, req.AgentID, req.TokenID, req.Resource, req.Reason,
		string(req.Status), req.WebhookURL, string(metadataJSON), req.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert approval request: %w", err)
	}
	return nil
}

func (s *PostgresApprovalStore) Get(ctx context.Context, id string) (*ApprovalRequest, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, agent_id, token_id, resource, reason, status, approver_id, decided_at, webhook_url, metadata, created_at
		 FROM approval_requests WHERE id = $1`, id)
	return scanApproval(row)
}

func (s *PostgresApprovalStore) Approve(ctx context.Context, id, approverID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE approval_requests SET status='approved', approver_id=$2, decided_at=NOW()
		 WHERE id=$1 AND status='pending'`,
		id, approverID,
	)
	if err != nil {
		return fmt.Errorf("approve request: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("approval %s not found or already decided", id)
	}
	return nil
}

func (s *PostgresApprovalStore) Deny(ctx context.Context, id, approverID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE approval_requests SET status='denied', approver_id=$2, decided_at=NOW()
		 WHERE id=$1 AND status='pending'`,
		id, approverID,
	)
	if err != nil {
		return fmt.Errorf("deny request: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("approval %s not found or already decided", id)
	}
	return nil
}

func (s *PostgresApprovalStore) ListPending(ctx context.Context, agentID string) ([]ApprovalRequest, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, agent_id, token_id, resource, reason, status, approver_id, decided_at, webhook_url, metadata, created_at
		 FROM approval_requests WHERE agent_id=$1 AND status='pending' ORDER BY created_at DESC`,
		agentID,
	)
	if err != nil {
		return nil, fmt.Errorf("list pending approvals: %w", err)
	}
	defer rows.Close()

	var result []ApprovalRequest
	for rows.Next() {
		req, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *req)
	}
	return result, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanApproval(row rowScanner) (*ApprovalRequest, error) {
	var req ApprovalRequest
	var status string
	var approverID *string
	var decidedAt *time.Time
	var webhookURL *string
	var metadataJSON *string

	err := row.Scan(
		&req.ID, &req.AgentID, &req.TokenID, &req.Resource, &req.Reason,
		&status, &approverID, &decidedAt, &webhookURL, &metadataJSON, &req.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan approval: %w", err)
	}

	req.Status = ApprovalStatus(status)
	if approverID != nil {
		req.ApproverID = *approverID
	}
	req.DecidedAt = decidedAt
	if webhookURL != nil {
		req.WebhookURL = *webhookURL
	}
	if metadataJSON != nil && *metadataJSON != "" && *metadataJSON != "null" {
		if err := json.Unmarshal([]byte(*metadataJSON), &req.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &req, nil
}

// MemoryApprovalStore implements ApprovalStore with in-memory storage for dev/test.
type MemoryApprovalStore struct {
	mu       sync.RWMutex
	requests map[string]*ApprovalRequest
}

// NewMemoryApprovalStore creates a new in-memory approval store.
func NewMemoryApprovalStore() *MemoryApprovalStore {
	return &MemoryApprovalStore{
		requests: make(map[string]*ApprovalRequest),
	}
}

func (s *MemoryApprovalStore) Create(_ context.Context, req *ApprovalRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.ID == "" {
		req.ID = uuid.New().String()
	}
	req.CreatedAt = time.Now()
	req.Status = StatusPending
	// Store a copy.
	copy := *req
	s.requests[req.ID] = &copy
	return nil
}

func (s *MemoryApprovalStore) Get(_ context.Context, id string) (*ApprovalRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.requests[id]
	if !ok {
		return nil, fmt.Errorf("approval %s not found", id)
	}
	copy := *req
	return &copy, nil
}

func (s *MemoryApprovalStore) Approve(_ context.Context, id, approverID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.requests[id]
	if !ok {
		return fmt.Errorf("approval %s not found", id)
	}
	if req.Status != StatusPending {
		return fmt.Errorf("approval %s already decided", id)
	}
	now := time.Now()
	req.Status = StatusApproved
	req.ApproverID = approverID
	req.DecidedAt = &now
	return nil
}

func (s *MemoryApprovalStore) Deny(_ context.Context, id, approverID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.requests[id]
	if !ok {
		return fmt.Errorf("approval %s not found", id)
	}
	if req.Status != StatusPending {
		return fmt.Errorf("approval %s already decided", id)
	}
	now := time.Now()
	req.Status = StatusDenied
	req.ApproverID = approverID
	req.DecidedAt = &now
	return nil
}

func (s *MemoryApprovalStore) ListPending(_ context.Context, agentID string) ([]ApprovalRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []ApprovalRequest
	for _, req := range s.requests {
		if req.AgentID == agentID && req.Status == StatusPending {
			result = append(result, *req)
		}
	}
	return result, nil
}
