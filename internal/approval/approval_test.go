package approval_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/agentity/agentity/internal/approval"
)

func newService(t *testing.T, serverBase string) *approval.ApprovalService {
	t.Helper()
	store := approval.NewMemoryApprovalStore()
	return approval.NewApprovalService(store, serverBase)
}

func TestApprovalLifecycle_Approve(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	ar, err := svc.RequestApproval(ctx, "agent-1", "tok-1", "s3://bucket/file", "need access", "")
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if ar.Status != approval.StatusPending {
		t.Fatalf("expected pending, got %s", ar.Status)
	}

	if err := svc.Approve(ctx, ar.ID, "admin@example.com"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	got, err := svc.Get(ctx, ar.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != approval.StatusApproved {
		t.Errorf("expected approved, got %s", got.Status)
	}
	if got.ApproverID != "admin@example.com" {
		t.Errorf("expected approver admin@example.com, got %s", got.ApproverID)
	}
	if got.DecidedAt == nil {
		t.Error("expected DecidedAt to be set")
	}
}

func TestApprovalLifecycle_Deny(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	ar, err := svc.RequestApproval(ctx, "agent-2", "tok-2", "rm -rf /", "cleanup", "")
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}

	if err := svc.Deny(ctx, ar.ID, "security@example.com"); err != nil {
		t.Fatalf("Deny: %v", err)
	}

	got, err := svc.Get(ctx, ar.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != approval.StatusDenied {
		t.Errorf("expected denied, got %s", got.Status)
	}
	if got.ApproverID != "security@example.com" {
		t.Errorf("expected approver security@example.com, got %s", got.ApproverID)
	}
}

func TestApprovalService_ListPending(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	agentID := "agent-list"
	var ids []string
	for i := 0; i < 3; i++ {
		ar, err := svc.RequestApproval(ctx, agentID, "tok", "res", "reason", "")
		if err != nil {
			t.Fatalf("RequestApproval %d: %v", i, err)
		}
		ids = append(ids, ar.ID)
	}

	// Approve the first one.
	if err := svc.Approve(ctx, ids[0], "approver"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	pending, err := svc.ListPending(ctx, agentID)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 2 {
		t.Errorf("expected 2 pending, got %d", len(pending))
	}
	for _, p := range pending {
		if p.Status != approval.StatusPending {
			t.Errorf("expected pending status, got %s", p.Status)
		}
	}
}

func TestApprovalService_WebhookFired(t *testing.T) {
	// Loopback and private addresses must be rejected by the SSRF guard.
	// httptest.NewServer binds to 127.0.0.1, which is in the blocked range.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data map[string]string
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &data)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	// Supplying a loopback webhook URL must be rejected with an SSRF validation error.
	_, err := svc.RequestApproval(ctx, "agent-wh", "tok-wh", "resource", "reason", srv.URL)
	if err == nil {
		t.Fatal("expected SSRF validation error for loopback webhook URL, got nil")
	}

	// Approval with no webhook URL must still succeed.
	ar, err := svc.RequestApproval(ctx, "agent-wh", "tok-wh", "resource", "reason", "")
	if err != nil {
		t.Fatalf("RequestApproval without webhook: %v", err)
	}
	if ar.Status != approval.StatusPending {
		t.Errorf("expected pending, got %s", ar.Status)
	}
}

func TestApprovalService_WebhookInvalidScheme(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	_, err := svc.RequestApproval(ctx, "agent-scheme", "tok-scheme", "resource", "reason", "ftp://example.com/hook")
	if err == nil {
		t.Fatal("expected error for non-http/https webhook URL, got nil")
	}

	// Variable declared to suppress unused import warning for time in this file.
	_ = time.Second
	_ = sync.Mutex{}
}

func TestApprovalService_AlreadyDecided(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	ar, err := svc.RequestApproval(ctx, "agent-dup", "tok-dup", "resource", "reason", "")
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}

	if err := svc.Approve(ctx, ar.ID, "approver"); err != nil {
		t.Fatalf("first Approve: %v", err)
	}

	// Second approve should fail.
	err = svc.Approve(ctx, ar.ID, "approver2")
	if err == nil {
		t.Fatal("expected error on second Approve, got nil")
	}
}

func TestApprovalService_Get_NotFound(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	_, err := svc.Get(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent ID, got nil")
	}
}

func TestApprovalService_Approve_NotFound(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	err := svc.Approve(ctx, "nonexistent-id", "approver")
	if err == nil {
		t.Fatal("expected error for nonexistent ID, got nil")
	}
}

func TestApprovalService_Deny_NotFound(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	err := svc.Deny(ctx, "nonexistent-id", "approver")
	if err == nil {
		t.Fatal("expected error for nonexistent ID, got nil")
	}
}

func TestApprovalService_ListPending_Empty(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	pending, err := svc.ListPending(ctx, "agent-no-requests")
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("expected empty slice, got %d items", len(pending))
	}
}

func TestApprovalService_ListPending_MultiAgent(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	// Create requests for agent-A.
	for i := 0; i < 2; i++ {
		_, err := svc.RequestApproval(ctx, "agent-A", "tok-A", "res", "reason", "")
		if err != nil {
			t.Fatalf("RequestApproval agent-A %d: %v", i, err)
		}
	}

	// Create requests for agent-B.
	_, err := svc.RequestApproval(ctx, "agent-B", "tok-B", "res", "reason", "")
	if err != nil {
		t.Fatalf("RequestApproval agent-B: %v", err)
	}

	pending, err := svc.ListPending(ctx, "agent-A")
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 2 {
		t.Errorf("expected 2 pending for agent-A, got %d", len(pending))
	}
	for _, p := range pending {
		if p.AgentID != "agent-A" {
			t.Errorf("expected agent-A, got %s", p.AgentID)
		}
	}
}

func TestApprovalService_Deny_ThenGetStatus(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	ar, err := svc.RequestApproval(ctx, "agent-deny-check", "tok-dc", "resource", "reason", "")
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}

	if err := svc.Deny(ctx, ar.ID, "security@example.com"); err != nil {
		t.Fatalf("Deny: %v", err)
	}

	got, err := svc.Get(ctx, ar.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != approval.StatusDenied {
		t.Errorf("expected denied, got %s", got.Status)
	}
	if got.ApproverID != "security@example.com" {
		t.Errorf("expected approverID security@example.com, got %s", got.ApproverID)
	}
	if got.DecidedAt == nil {
		t.Error("expected DecidedAt to be set after deny")
	}
}

func TestWebhookURL_InvalidScheme_FTP(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	_, err := svc.RequestApproval(ctx, "agent-ftp", "tok-ftp", "resource", "reason", "ftp://example.com/hook")
	if err == nil {
		t.Fatal("expected error for ftp:// webhook URL, got nil")
	}
}

func TestWebhookURL_InvalidScheme_File(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	_, err := svc.RequestApproval(ctx, "agent-file", "tok-file", "resource", "reason", "file:///etc/passwd")
	if err == nil {
		t.Fatal("expected error for file:// webhook URL, got nil")
	}
}

func TestWebhookURL_PrivateIP_10x(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	_, err := svc.RequestApproval(ctx, "agent-priv10", "tok-priv10", "resource", "reason", "http://10.0.0.1/hook")
	if err == nil {
		t.Fatal("expected error for private IP 10.0.0.1 webhook URL, got nil")
	}
}

func TestWebhookURL_PrivateIP_192168(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	_, err := svc.RequestApproval(ctx, "agent-priv192", "tok-priv192", "resource", "reason", "http://192.168.1.1/hook")
	if err == nil {
		t.Fatal("expected error for private IP 192.168.1.1 webhook URL, got nil")
	}
}

func TestWebhookURL_Localhost(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	_, err := svc.RequestApproval(ctx, "agent-lo", "tok-lo", "resource", "reason", "http://127.0.0.1/hook")
	if err == nil {
		t.Fatal("expected error for loopback 127.0.0.1 webhook URL, got nil")
	}
}

func TestWebhookURL_NoWebhook_Succeeds(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	ar, err := svc.RequestApproval(ctx, "agent-nowh", "tok-nowh", "resource", "reason", "")
	if err != nil {
		t.Fatalf("expected success with empty webhookURL, got: %v", err)
	}
	if ar.Status != approval.StatusPending {
		t.Errorf("expected pending, got %s", ar.Status)
	}
}

func TestApprovalService_AlreadyDenied_SecondDeny(t *testing.T) {
	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	ar, err := svc.RequestApproval(ctx, "agent-dd", "tok-dd", "resource", "reason", "")
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}

	if err := svc.Deny(ctx, ar.ID, "denier"); err != nil {
		t.Fatalf("first Deny: %v", err)
	}

	err = svc.Deny(ctx, ar.ID, "denier2")
	if err == nil {
		t.Fatal("expected error on second Deny of already-denied request, got nil")
	}
}
