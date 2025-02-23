package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Port          string
	RedisAddress  string
	RedisPassword string
	JWTSecret     string
	TokenStore    string // Add TokenStore field
}

func LoadConfig(envPath string) (*Config, error) {
	// attempt to load env vars from file
	_ = godotenv.Load(envPath)

	cfg := &Config{
		Port:          os.Getenv("PORT"),
		RedisAddress:  os.Getenv("REDIS_ADDRESS"),
		RedisPassword: os.Getenv("REDIS_PASSWORD"),
		JWTSecret:     os.Getenv("JWT_SECRET"),
		TokenStore:    os.Getenv("TOKEN_STORE"), // Get TOKEN_STORE
	}
	if cfg.TokenStore == "" {
		return nil, fmt.Errorf("TOKEN_STORE environment variable must be set ('redis' or 'inmemory')")
	}

	return cfg, nil
}
