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
	var mu sync.Mutex
	var received map[string]string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var data map[string]string
		_ = json.Unmarshal(body, &data)
		mu.Lock()
		received = data
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := newService(t, "http://localhost:8080")
	ctx := context.Background()

	ar, err := svc.RequestApproval(ctx, "agent-wh", "tok-wh", "resource", "reason", srv.URL)
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}

	// Webhook fires in goroutine; give it a moment.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := received
		mu.Unlock()
		if got != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	got := received
	mu.Unlock()

	if got == nil {
		t.Fatal("webhook was not fired within 2 seconds")
	}
	if got["approval_id"] != ar.ID {
		t.Errorf("webhook approval_id: got %s, want %s", got["approval_id"], ar.ID)
	}
	if got["agent_id"] != "agent-wh" {
		t.Errorf("webhook agent_id: got %s, want agent-wh", got["agent_id"])
	}
	expectedApproveURL := "http://localhost:8080/api/v1/approvals/" + ar.ID + "/approve"
	if got["approve_url"] != expectedApproveURL {
		t.Errorf("webhook approve_url: got %s, want %s", got["approve_url"], expectedApproveURL)
	}
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
