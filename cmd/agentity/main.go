package main

import (
	"context"
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
	"github.com/redis/go-redis/v9"
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
	rootCmd.Flags().BoolVar(&devMode, "dev", false, "Enable development mode (in-memory store, auto-generated keys, hardcoded admin key)")
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

		// C2 fix: refuse to start in production if admin key is not configured.
		if cfg.Auth.AdminAPIKey == "" {
			return fmt.Errorf("AGENTITY_AUTH_ADMIN_API_KEY must be set in production mode")
		}
	}

	if logLevel != "info" {
		cfg.Log.Level = logLevel
	}

	// Set up logger.
	level, _ := zerolog.ParseLevel(cfg.Log.Level)
	var logger zerolog.Logger
	if cfg.Log.Format == "console" {
		logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).
			Level(level).With().Timestamp().Str("service", "agentity").Logger()
	} else {
		logger = zerolog.New(os.Stdout).
			Level(level).With().Timestamp().Str("service", "agentity").Logger()
	}

	// C5 fix: initialize root key store from file in production, ephemeral in dev.
	var rootKeyStore *agcrypto.RootKeyStore
	if devMode {
		rootKeyStore, err = agcrypto.NewRootKeyStore()
		if err != nil {
			return fmt.Errorf("create ephemeral root key: %w", err)
		}
		logger.Warn().
			Str("key_id", rootKeyStore.KeyID()).
			Str("admin_key", cfg.Auth.AdminAPIKey).
			Msg("DEV MODE: ephemeral root key (not suitable for production)")
	} else {
		if cfg.Crypto.RootKeyFile == "" {
			return fmt.Errorf("AGENTITY_CRYPTO_ROOT_KEY_FILE must be set in production mode")
		}
		rootKeyStore, err = agcrypto.LoadOrCreateRootKeyStore(cfg.Crypto.RootKeyFile)
		if err != nil {
			return fmt.Errorf("load root key store from %s: %w", cfg.Crypto.RootKeyFile, err)
		}
		logger.Info().
			Str("key_id", rootKeyStore.KeyID()).
			Str("key_file", cfg.Crypto.RootKeyFile).
			Msg("root key loaded")
	}

	// M8 fix: select the store backend based on configuration.
	var agentStore identity.Store
	var readinessCheck func() error

	switch cfg.Store.Type {
	case "postgres":
		if cfg.Store.DSN == "" {
			return fmt.Errorf("store.dsn must be set when store.type=postgres")
		}
		pgStore, err := store.NewPostgresStore(context.Background(), cfg.Store.DSN, cfg.Store.MaxConns)
		if err != nil {
			return fmt.Errorf("connect to postgres: %w", err)
		}
		agentStore = pgStore
		readinessCheck = func() error { return pgStore.Ping(context.Background()) }
		logger.Info().Str("dsn_host", extractHost(cfg.Store.DSN)).Msg("using postgres store")
	default:
		agentStore = store.NewMemoryStore()
		logger.Info().Msg("using in-memory store (data is not persisted across restarts)")
	}

	// Initialize Redis revocation registry if configured.
	var redisClient *redis.Client
	if cfg.Redis.Enabled {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     cfg.Redis.Address,
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		})
		if err := redisClient.Ping(context.Background()).Err(); err != nil {
			return fmt.Errorf("connect to redis at %s: %w", cfg.Redis.Address, err)
		}
		logger.Info().Str("addr", cfg.Redis.Address).Msg("using redis for revocation registry")
	}
	revReg := revocation.NewRegistry(redisClient)

	// Initialize services.
	auditLog := audit.NewLogger(rootKeyStore.PrivateKey())
	idService := identity.NewService(agentStore)
	keyResolver := delegation.NewKeyResolver(rootKeyStore, agentStore)
	delegEngine := delegation.NewEngine(agentStore, revReg, auditLog, keyResolver)

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
		AllowedOrigins:   []string{"*"}, // restrict in production via config
		ReadinessCheck:   readinessCheck,
	})

	srv := server.New(router, cfg.Server, logger)

	logger.Info().
		Int("port", cfg.Server.Port).
		Str("store", cfg.Store.Type).
		Bool("dev_mode", devMode).
		Msg("Agentity server starting")

	return srv.Start()
}

// extractHost returns a safe host string from a DSN for logging (no passwords).
func extractHost(dsn string) string {
	for i, c := range dsn {
		if c == '@' {
			return dsn[i+1:]
		}
	}
	return dsn
}
