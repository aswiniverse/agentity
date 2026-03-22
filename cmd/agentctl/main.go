package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/agentity/agentity/pkg/sdk"
	"github.com/agentity/agentity/pkg/token"
	"github.com/spf13/cobra"
)

var (
	serverURL string
	adminKey  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "agentctl",
		Short: "Agentity CLI - manage agents, tokens, and policies",
	}

	rootCmd.PersistentFlags().StringVar(&serverURL, "server",
		envOrDefault("AGENTITY_SERVER", "http://localhost:8080"),
		"Agentity server URL")

	// M1 fix: no hardcoded default for the admin key.
	// Users must supply it via AGENTITY_ADMIN_KEY env var or --admin-key flag.
	rootCmd.PersistentFlags().StringVar(&adminKey, "admin-key",
		os.Getenv("AGENTITY_ADMIN_KEY"),
		"Admin API key (required; set via AGENTITY_ADMIN_KEY env var)")

	rootCmd.AddCommand(agentsCmd())
	rootCmd.AddCommand(tokensCmd())
	rootCmd.AddCommand(adminCmd())
	rootCmd.AddCommand(auditCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func requireAdminKey() error {
	if adminKey == "" {
		return fmt.Errorf("admin key is required: set AGENTITY_ADMIN_KEY env var or --admin-key flag")
	}
	return nil
}

func newClient() *sdk.Client {
	return sdk.NewClient(serverURL, adminKey)
}

func agentsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agents",
		Short: "Manage agent identities",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all agents",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := requireAdminKey(); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := doRawGet(ctx, "/api/v1/agents")
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		},
	}

	var (
		agentName  string
		agentModel string
		agentTools string
		agentDesc  string
	)
	registerCmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new agent",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := requireAdminKey(); err != nil {
				return err
			}
			client := newClient()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			var tools []string
			if agentTools != "" {
				tools = strings.Split(agentTools, ",")
			}

			agent, privKey, err := client.RegisterAgent(ctx, sdk.RegisterAgentRequest{
				Name:        agentName,
				Description: agentDesc,
				Model:       agentModel,
				Tools:       tools,
			})
			if err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "WARNING: Store the private key securely — it will not be shown again.\n")
			printJSON(map[string]interface{}{
				"agent":       agent,
				"private_key": privKey,
			})
			return nil
		},
	}
	registerCmd.Flags().StringVar(&agentName, "name", "", "Agent name (required)")
	registerCmd.Flags().StringVar(&agentModel, "model", "", "Model identifier")
	registerCmd.Flags().StringVar(&agentTools, "tools", "", "Comma-separated tool list")
	registerCmd.Flags().StringVar(&agentDesc, "description", "", "Agent description")
	_ = registerCmd.MarkFlagRequired("name")

	getCmd := &cobra.Command{
		Use:   "get [id]",
		Short: "Get agent details",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := requireAdminKey(); err != nil {
				return err
			}
			client := newClient()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			agent, err := client.GetAgent(ctx, args[0])
			if err != nil {
				return err
			}
			printJSON(agent)
			return nil
		},
	}

	var cascade bool
	revokeCmd := &cobra.Command{
		Use:   "revoke [id]",
		Short: "Revoke an agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := requireAdminKey(); err != nil {
				return err
			}
			client := newClient()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := client.RevokeAgent(ctx, args[0], cascade); err != nil {
				return err
			}
			fmt.Println("Agent revoked successfully")
			return nil
		},
	}
	revokeCmd.Flags().BoolVar(&cascade, "cascade", false, "Also revoke all child agents")

	cmd.AddCommand(listCmd, registerCmd, getCmd, revokeCmd)
	return cmd
}

func tokensCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tokens",
		Short: "Manage tokens",
	}

	var (
		tokenAgentID string
		tokenCaps    string
		tokenTTL     string
	)
	issueCmd := &cobra.Command{
		Use:   "issue",
		Short: "Issue a root token for an agent",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := requireAdminKey(); err != nil {
				return err
			}
			client := newClient()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ttl, err := time.ParseDuration(tokenTTL)
			if err != nil {
				return fmt.Errorf("invalid TTL: %w", err)
			}

			caps := strings.Split(tokenCaps, ",")
			encoded, err := client.IssueToken(ctx, sdk.IssueTokenRequest{
				AgentID:      tokenAgentID,
				Capabilities: caps,
				Conditions: token.BlockConditions{
					ExpiresAt: time.Now().Add(ttl).Unix(),
				},
			})
			if err != nil {
				return err
			}
			fmt.Printf("Token: %s\n", encoded)
			return nil
		},
	}
	issueCmd.Flags().StringVar(&tokenAgentID, "agent", "", "Agent ID (required)")
	issueCmd.Flags().StringVar(&tokenCaps, "caps", "", "Comma-separated capabilities (required)")
	issueCmd.Flags().StringVar(&tokenTTL, "ttl", "1h", "Token TTL (e.g. 1h, 24h)")
	_ = issueCmd.MarkFlagRequired("agent")
	_ = issueCmd.MarkFlagRequired("caps")

	verifyCmd := &cobra.Command{
		Use:   "verify [token]",
		Short: "Verify a token",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := requireAdminKey(); err != nil {
				return err
			}
			client := newClient()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result, err := client.VerifyToken(ctx, args[0])
			if err != nil {
				return err
			}
			printJSON(result)
			return nil
		},
	}

	var revokeReason string
	revokeTokenCmd := &cobra.Command{
		Use:   "revoke [token-id]",
		Short: "Revoke a token by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := requireAdminKey(); err != nil {
				return err
			}
			client := newClient()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := client.RevokeToken(ctx, args[0], revokeReason); err != nil {
				return err
			}
			fmt.Println("Token revoked successfully")
			return nil
		},
	}
	revokeTokenCmd.Flags().StringVar(&revokeReason, "reason", "", "Revocation reason")

	cmd.AddCommand(issueCmd, verifyCmd, revokeTokenCmd)
	return cmd
}

func adminCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Admin operations",
	}

	statsCmd := &cobra.Command{
		Use:   "stats",
		Short: "Show system statistics",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := requireAdminKey(); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := doRawGet(ctx, "/api/v1/admin/stats")
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		},
	}

	policiesCmd := &cobra.Command{
		Use:   "policies",
		Short: "Manage policies",
	}

	policiesListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all policies",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := requireAdminKey(); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := doRawGet(ctx, "/api/v1/admin/policies")
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		},
	}

	var (
		policyName     string
		policyExpr     string
		policyAction   string
		policyPriority int
	)
	policiesCreateCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a policy",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := requireAdminKey(); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			body := map[string]interface{}{
				"name":       policyName,
				"expression": policyExpr,
				"action":     policyAction,
				"priority":   policyPriority,
			}
			resp, err := doRawPost(ctx, "/api/v1/admin/policies", body)
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		},
	}
	policiesCreateCmd.Flags().StringVar(&policyName, "name", "", "Policy name (required)")
	policiesCreateCmd.Flags().StringVar(&policyExpr, "expr", "", "CEL expression (required)")
	policiesCreateCmd.Flags().StringVar(&policyAction, "action", "allow", "Action (allow/deny)")
	policiesCreateCmd.Flags().IntVar(&policyPriority, "priority", 0, "Priority (higher = evaluated first)")
	_ = policiesCreateCmd.MarkFlagRequired("name")
	_ = policiesCreateCmd.MarkFlagRequired("expr")

	policiesCmd.AddCommand(policiesListCmd, policiesCreateCmd)
	cmd.AddCommand(statsCmd, policiesCmd)
	return cmd
}

func auditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit log operations",
	}

	var limit int
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List audit log entries",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := requireAdminKey(); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			path := fmt.Sprintf("/api/v1/audit?limit=%d", limit)
			resp, err := doRawGet(ctx, path)
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		},
	}
	listCmd.Flags().IntVar(&limit, "limit", 20, "Maximum number of audit entries to return")

	cmd.AddCommand(listCmd)
	return cmd
}

func printJSON(v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		return
	}
	fmt.Println(string(data))
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func doRawGet(ctx context.Context, path string) (interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+adminKey)
	return doHTTP(req)
}

func doRawPost(ctx context.Context, path string, body interface{}) (interface{}, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminKey)
	return doHTTP(req)
}

func doHTTP(req *http.Request) (interface{}, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}
	return result, nil
}
