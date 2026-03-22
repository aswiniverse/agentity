package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the top-level application configuration.
type Config struct {
	Server ServerConfig `mapstructure:"server"`
	Store  StoreConfig  `mapstructure:"store"`
	Redis  RedisConfig  `mapstructure:"redis"`
	Crypto CryptoConfig `mapstructure:"crypto"`
	Auth   AuthConfig   `mapstructure:"auth"`
	Log    LogConfig    `mapstructure:"log"`
	OTEL   OTELConfig   `mapstructure:"otel"`
	OIDC   OIDCConfig   `mapstructure:"oidc"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	TLSCertFile     string        `mapstructure:"tls_cert_file"`
	TLSKeyFile      string        `mapstructure:"tls_key_file"`
}

// StoreConfig holds data store settings.
type StoreConfig struct {
	Type     string `mapstructure:"type"` // "memory" or "postgres"
	DSN      string `mapstructure:"dsn"`
	MaxConns int    `mapstructure:"max_conns"`
}

// RedisConfig holds Redis connection settings.
type RedisConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Address  string `mapstructure:"address"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

// CryptoConfig holds cryptographic settings.
type CryptoConfig struct {
	RootKeyFile string `mapstructure:"root_key_file"`
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	AdminAPIKey string `mapstructure:"admin_api_key"`
}

// LogConfig holds logging settings.
type LogConfig struct {
	Level  string `mapstructure:"level"`  // debug, info, warn, error
	Format string `mapstructure:"format"` // json, console
}

// OTELConfig holds OpenTelemetry settings.
type OTELConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	ServiceName  string `mapstructure:"service_name"`
	ExporterType string `mapstructure:"exporter_type"` // stdout, otlp
	Endpoint     string `mapstructure:"endpoint"`
}

// OIDCConfig holds OpenID Connect settings.
type OIDCConfig struct {
	// IssuerURL is the base URL for OIDC discovery (AGENTITY_OIDC_ISSUER_URL).
	IssuerURL string `mapstructure:"issuer_url"`
}

// Load reads configuration from file, environment, and flags.
func Load(configFile string) (*Config, error) {
	v := viper.New()

	// Defaults.
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", 30*time.Second)
	v.SetDefault("server.write_timeout", 30*time.Second)
	v.SetDefault("server.shutdown_timeout", 15*time.Second)
	v.SetDefault("store.type", "memory")
	v.SetDefault("store.max_conns", 20)
	v.SetDefault("redis.enabled", false)
	v.SetDefault("redis.address", "localhost:6379")
	v.SetDefault("redis.db", 0)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("otel.enabled", false)
	v.SetDefault("otel.service_name", "agentity")
	v.SetDefault("otel.exporter_type", "stdout")

	// Environment variables (AGENTITY_SERVER_PORT, etc.).
	v.SetEnvPrefix("AGENTITY")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Config file.
	if configFile != "" {
		v.SetConfigFile(configFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	return &cfg, nil
}

// LoadDev returns a configuration suitable for development mode.
func LoadDev(port int) *Config {
	cfg := &Config{
		Server: ServerConfig{
			Host:            "0.0.0.0",
			Port:            port,
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    30 * time.Second,
			ShutdownTimeout: 5 * time.Second,
		},
		Store: StoreConfig{
			Type: "memory",
		},
		Redis: RedisConfig{
			Enabled: false,
		},
		Auth: AuthConfig{
			AdminAPIKey: "dev-admin-key",
		},
		Log: LogConfig{
			Level:  "debug",
			Format: "console",
		},
		OTEL: OTELConfig{
			Enabled:     false,
			ServiceName: "agentity-dev",
		},
	}
	return cfg
}
