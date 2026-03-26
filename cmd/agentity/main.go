package main

import (
	"context"
	"fmt"
	"os"

	"github.com/agentity/agentity/internal/api"
	"github.com/agentity/agentity/internal/approval"
	"github.com/agentity/agentity/internal/audit"
	"github.com/agentity/agentity/internal/config"
	"github.com/agentity/agentity/internal/delegation"
	"github.com/agentity/agentity/internal/identity"
	"github.com/agentity/agentity/internal/policy"
	"github.com/agentity/agentity/internal/revocation"
	"github.com/agentity/agentity/internal/server"
	"github.com/agentity/agentity/internal/store"
	"github.com/agentity/agentity/internal/user"
	"github.com/agentity/agentity/internal/vault"
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
		cfg.Dev = true
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
	var pgStore *store.PostgresStore

	var auditStore audit.AuditStore
	switch cfg.Store.Type {
	case "postgres":
		if cfg.Store.DSN == "" {
			return fmt.Errorf("store.dsn must be set when store.type=postgres")
		}
		pgStore, err = store.NewPostgresStore(context.Background(), cfg.Store.DSN, cfg.Store.MaxConns)
		if err != nil {
			return fmt.Errorf("connect to postgres: %w", err)
		}
		agentStore = pgStore
		auditStore = audit.NewPostgresAuditStore(pgStore.Pool())
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
	auditLog := audit.NewLogger(rootKeyStore.PrivateKey(), auditStore)
	idService := identity.NewService(agentStore)
	keyResolver := delegation.NewKeyResolver(rootKeyStore, agentStore)
	delegEngine := delegation.NewEngine(agentStore, revReg, auditLog, keyResolver)

	var policyEngine *policy.Engine
	if pgStore != nil {
		policyStore := policy.NewPostgresPolicyStore(pgStore.Pool())
		policyEngine, err = policy.NewEngineWithStore(policyStore)
		if err != nil {
			return fmt.Errorf("create policy engine: %w", err)
		}
		if loadErr := policyEngine.LoadFromStore(context.Background()); loadErr != nil {
			logger.Error().Err(loadErr).Msg("failed to load policies from store; enforcing deny-all until store recovers")
		}
	} else {
		policyEngine, err = policy.NewEngine()
		if err != nil {
			return fmt.Errorf("create policy engine: %w", err)
		}
	}

	// Initialize user store and service.
	var userStore user.UserStore
	if pgStore != nil {
		userStore = user.NewPostgresUserStore(pgStore.Pool())
	} else {
		userStore = user.NewMemoryUserStore()
	}
	userService := user.NewUserService(userStore)

	// Initialize vault service if AGENTITY_VAULT_KEY is set.
	var vaultService *vault.VaultService
	if vaultEncryptor, vaultErr := vault.NewLocalEncryptorFromEnv(); vaultErr == nil {
		var vaultStore vault.VaultStore
		if pgStore != nil {
			vaultStore = vault.NewPostgresVaultStore(pgStore.Pool())
		} else {
			vaultStore = vault.NewMemoryVaultStore()
		}
		vaultService = vault.NewVaultService(vaultStore, vaultEncryptor)
		logger.Info().Msg("vault service initialized")
	} else {
		logger.Warn().Msg("AGENTITY_VAULT_KEY not set; credential vault endpoints disabled")
	}

	// Initialize approval service; use postgres store when available so approval
	// requests survive restarts.
	var approvalStore approval.ApprovalStore
	if pgStore != nil {
		approvalStore = approval.NewPostgresApprovalStore(pgStore.Pool())
	} else {
		approvalStore = approval.NewMemoryApprovalStore()
	}

	// serverBase is the externally-reachable URL used for approve/deny webhook links.
	// AGENTITY_SERVER_SERVER_URL must be set in production; falls back to localhost for dev.
	serverBase := cfg.Server.ServerURL
	if serverBase == "" {
		serverBase = fmt.Sprintf("http://localhost:%d", cfg.Server.Port)
		if !devMode {
			logger.Warn().Msg("AGENTITY_SERVER_SERVER_URL is not set; approval webhook links will point to localhost and may not be reachable")
		}
	}
	approvalService := approval.NewApprovalService(approvalStore, serverBase)

	// Build router.
	router := api.NewRouter(api.RouterConfig{
		Logger:           logger,
		RootKeyStore:     rootKeyStore,
		IdentityService:  idService,
		DelegationEngine: delegEngine,
		RevocationReg:    revReg,
		PolicyEngine:     policyEngine,
		AuditLogger:      auditLog,
		KeyResolver:      keyResolver,
		UserService:      userService,
		VaultService:     vaultService,
		ApprovalService:  approvalService,
		AdminAPIKey:      cfg.Auth.AdminAPIKey,
		IssuerURL:        cfg.OIDC.IssuerURL,
		AllowedOrigins:   corsOrigins(cfg, devMode),
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

// corsOrigins returns the allowed CORS origins based on configuration.
// In dev mode, defaults to ["*"] if not explicitly configured.
// In production, if no origins are set, warns and uses the server's own origin.
func corsOrigins(cfg *config.Config, devMode bool) []string {
	if len(cfg.AllowedOrigins) > 0 {
		return cfg.AllowedOrigins
	}
	if devMode {
		return []string{"*"}
	}
	// Production with no origins configured: default to own origin only.
	fmt.Fprintf(os.Stderr, "WARN: AGENTITY_CORS_ALLOWED_ORIGINS is not set; defaulting to server's own origin\n")
	return []string{fmt.Sprintf("http://localhost:%d", cfg.Server.Port)}
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
