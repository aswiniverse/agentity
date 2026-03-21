package main

import (
	"fmt"
	"os"

	"github.com/agentity/agentity/internal/api"
	"github.com/agentity/agentity/internal/audit"
	"github.com/agentity/agentity/internal/config"
	"github.com/agentity/agentity/internal/delegation"
	"github.com/agentity/agentity/internal/identity"
	"github.com/agentity/agentity/internal/policy"
	"github.com/agentity/agentity/internal/revocation"
	"github.com/agentity/agentity/internal/server"
	"github.com/agentity/agentity/internal/store"
	agcrypto "github.com/agentity/agentity/pkg/crypto"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func main() {
	var (
		configFile string
		devMode    bool
		port       int
		logLevel   string
	)

	rootCmd := &cobra.Command{
		Use:   "agentity",
		Short: "Agentity - Agent-native Identity & Access Management",
		Long:  "Agentity is the first purpose-built, open-source IAM system for AI agents.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServer(configFile, devMode, port, logLevel)
		},
	}

	rootCmd.Flags().StringVar(&configFile, "config", "", "Path to configuration file")
	rootCmd.Flags().BoolVar(&devMode, "dev", false, "Enable development mode (in-memory store, auto-generated keys)")
	rootCmd.Flags().IntVar(&port, "port", 8080, "Server port")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runServer(configFile string, devMode bool, port int, logLevel string) error {
	// Load configuration.
	var cfg *config.Config
	var err error

	if devMode {
		cfg = config.LoadDev(port)
	} else {
		cfg, err = config.Load(configFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		if port != 8080 {
			cfg.Server.Port = port
		}
	}

	// Override log level if specified.
	if logLevel != "info" {
		cfg.Log.Level = logLevel
	}

	// Set up logger.
	var logger zerolog.Logger
	level, err := zerolog.ParseLevel(cfg.Log.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}

	if cfg.Log.Format == "console" {
		logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).
			Level(level).
			With().
			Timestamp().
			Str("service", "agentity").
			Logger()
	} else {
		logger = zerolog.New(os.Stdout).
			Level(level).
			With().
			Timestamp().
			Str("service", "agentity").
			Logger()
	}

	// Initialize root key store.
	rootKeyStore, err := agcrypto.NewRootKeyStore()
	if err != nil {
		return fmt.Errorf("create root key store: %w", err)
	}

	if devMode {
		logger.Info().
			Str("key_id", rootKeyStore.KeyID()).
			Str("admin_key", cfg.Auth.AdminAPIKey).
			Msg("dev mode: ephemeral root key generated")
	}

	// Initialize store.
	memStore := store.NewMemoryStore()

	// Initialize revocation registry (no Redis in dev mode).
	revReg := revocation.NewRegistry(nil)

	// Initialize audit logger.
	auditLog := audit.NewLogger(rootKeyStore.PrivateKey())

	// Initialize identity service.
	idService := identity.NewService(memStore)

	// Initialize key resolver.
	keyResolver := delegation.NewKeyResolver(rootKeyStore, memStore)

	// Initialize delegation engine.
	delegEngine := delegation.NewEngine(memStore, revReg, auditLog, keyResolver)

	// Initialize policy engine.
	policyEngine, err := policy.NewEngine()
	if err != nil {
		return fmt.Errorf("create policy engine: %w", err)
	}

	// Build router.
	router := api.NewRouter(api.RouterConfig{
		Logger:           logger,
		RootKeyStore:     rootKeyStore,
		IdentityService:  idService,
		DelegationEngine: delegEngine,
		RevocationReg:    revReg,
		PolicyEngine:     policyEngine,
		AuditLogger:      auditLog,
		AdminAPIKey:      cfg.Auth.AdminAPIKey,
	})

	// Create and start server.
	srv := server.New(router, cfg.Server, logger)

	logger.Info().
		Int("port", cfg.Server.Port).
		Str("store", cfg.Store.Type).
		Bool("dev_mode", devMode).
		Msg("Agentity server starting")

	return srv.Start()
}
