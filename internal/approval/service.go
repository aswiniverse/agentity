package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ApprovalService provides business logic for human approval gates.
type ApprovalService struct {
	store      ApprovalStore
	serverBase string // base URL for approve/deny links, e.g. "http://localhost:8080"
}

// NewApprovalService creates a new ApprovalService.
func NewApprovalService(store ApprovalStore, serverBase string) *ApprovalService {
	return &ApprovalService{store: store, serverBase: serverBase}
}

// privateIPNets contains the IP ranges that must be blocked for SSRF protection.
var privateIPNets []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
	} {
		_, ipNet, _ := net.ParseCIDR(cidr)
		privateIPNets = append(privateIPNets, ipNet)
	}
}

// validateWebhookURL rejects non-http/https schemes, empty hosts, and private/link-local IPs.
func validateWebhookURL(u string) error {
	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("webhook URL scheme must be http or https, got %q", parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("webhook URL has empty host")
	}
	// Resolve host to IP(s) and check for private ranges.
	ips, err := net.LookupIP(host)
	if err != nil {
		// If we cannot resolve, allow it through — DNS may be unavailable at validation time.
		return nil
	}
	for _, ip := range ips {
		for _, block := range privateIPNets {
			if block.Contains(ip) {
				return fmt.Errorf("webhook URL resolves to private/link-local address %s", ip)
			}
		}
	}
	return nil
}

// RequestApproval creates an approval request and optionally fires a webhook (non-blocking).
func (s *ApprovalService) RequestApproval(ctx context.Context, agentID, tokenID, resource, reason, webhookURL string) (*ApprovalRequest, error) {
	req := &ApprovalRequest{
		AgentID:    agentID,
		TokenID:    tokenID,
		Resource:   resource,
		Reason:     reason,
		WebhookURL: webhookURL,
	}
	if err := s.store.Create(ctx, req); err != nil {
		return nil, fmt.Errorf("create approval request: %w", err)
	}

	if webhookURL != "" {
		if err := validateWebhookURL(webhookURL); err != nil {
			return nil, fmt.Errorf("webhook URL validation failed: %w", err)
		}
		go s.fireWebhook(req)
	}

	return req, nil
}

func (s *ApprovalService) fireWebhook(req *ApprovalRequest) {
	payload := map[string]string{
		"approval_id": req.ID,
		"agent_id":    req.AgentID,
		"resource":    req.Resource,
		"reason":      req.Reason,
		"approve_url": fmt.Sprintf("%s/api/v1/approvals/%s/approve", s.serverBase, req.ID),
		"deny_url":    fmt.Sprintf("%s/api/v1/approvals/%s/deny", s.serverBase, req.ID),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("approval webhook: marshal payload: %v", err)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(req.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("approval webhook: POST %s: %v", req.WebhookURL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("approval webhook: POST %s returned status %d", req.WebhookURL, resp.StatusCode)
	}
}

// Approve marks an approval request as approved.
func (s *ApprovalService) Approve(ctx context.Context, id, approverID string) error {
	return s.store.Approve(ctx, id, approverID)
}

// Deny marks an approval request as denied.
func (s *ApprovalService) Deny(ctx context.Context, id, approverID string) error {
	return s.store.Deny(ctx, id, approverID)
}

// ListPending returns all pending approval requests for an agent.
func (s *ApprovalService) ListPending(ctx context.Context, agentID string) ([]ApprovalRequest, error) {
	return s.store.ListPending(ctx, agentID)
}

// Get retrieves a single approval request by ID.
func (s *ApprovalService) Get(ctx context.Context, id string) (*ApprovalRequest, error) {
	return s.store.Get(ctx, id)
}
