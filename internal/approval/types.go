package approval

import "time"

// ApprovalStatus represents the state of an approval request.
type ApprovalStatus string

const (
	StatusPending  ApprovalStatus = "pending"
	StatusApproved ApprovalStatus = "approved"
	StatusDenied   ApprovalStatus = "denied"
)

// ApprovalRequest represents a human approval gate for an agent action.
type ApprovalRequest struct {
	ID         string
	AgentID    string
	TokenID    string
	Resource   string
	Reason     string
	Status     ApprovalStatus
	ApproverID string
	DecidedAt  *time.Time
	WebhookURL string
	Metadata   map[string]interface{}
	CreatedAt  time.Time
}
