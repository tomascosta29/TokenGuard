package config

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Port               string  `mapstructure:"PORT"`
	RedisAddress       string  `mapstructure:"REDIS_ADDRESS"`
	RedisPassword      string  `mapstructure:"REDIS_PASSWORD"`
	JWTSecret          string  `mapstructure:"JWT_SECRET"`
	TokenStore         string  `mapstructure:"TOKEN_STORE"`
	DBPath             string  `mapstructure:"DB_PATH"`
	MTLSEnabled        bool    `mapstructure:"MTLS_ENABLED"`
	ServerCertFile     string  `mapstructure:"SERVER_CERT_FILE"`
	ServerKeyFile      string  `mapstructure:"SERVER_KEY_FILE"`
	CACertFile         string  `mapstructure:"CA_CERT_FILE"`
	RateLimit          float64 `mapstructure:"RATE_LIMIT"`
	RateBurst          int     `mapstructure:"RATE_BURST"`
	RateLimiterEnabled bool    `mapstructure:"RATE_LIMITER_ENABLED"`
	AdminAPIKey        string  `mapstructure:"ADMIN_API_KEY"`
}

func LoadConfig(path string) (*Config, error) {
	slog.Info("Loading configuration...", "path", path)

	// Set default values
	viper.SetDefault("PORT", "8080")
	viper.SetDefault("TOKEN_STORE", "inmemory")
	viper.SetDefault("DB_PATH", "auth.db")
	viper.SetDefault("RATE_LIMITER_ENABLED", true)
	viper.SetDefault("RATE_LIMIT", 10.0)
	viper.SetDefault("RATE_BURST", 5)
	viper.SetDefault("MTLS_ENABLED", false)
	viper.SetDefault("ADMIN_API_KEY", "default-admin-key")

	// Configure Viper to read from a file
	viper.AddConfigPath(path)
	viper.SetConfigName(".env")
	viper.SetConfigType("env")

	// Configure Viper to automatically read from environment variables
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Read the config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			slog.Warn("Config file not found; relying on environment variables and defaults.")
		} else {
			return nil, err
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	if cfg.MTLSEnabled {
		if cfg.ServerCertFile == "" || cfg.ServerKeyFile == "" || cfg.CACertFile == "" {
			err := fmt.Errorf("MTLS_ENABLED is true, but SERVER_CERT_FILE, SERVER_KEY_FILE, and CA_CERT_FILE are not all set")
			slog.Error(err.Error())
			return nil, err
		}
	}

	slog.Info("Configuration loaded successfully.")
	return &cfg, nil
}
