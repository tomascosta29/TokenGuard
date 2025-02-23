// File: /home/fcosta/CostaAuth/./internal/config/config.go
package config

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Port           string
	RedisAddress   string
	RedisPassword  string
	JWTSecret      string
	TokenStore     string
	MTLSEnabled    bool   // mTLS enabled flag
	ServerCertFile string // Path to server cert
	ServerKeyFile  string // Path to server key
	CACertFile     string // Path to CA cert
}

func LoadConfig(envPath string) (*Config, error) {
	log.Println("Loading configuration from environment...")

	_ = godotenv.Load(envPath)

	cfg := &Config{
		Port:           os.Getenv("PORT"),
		RedisAddress:   os.Getenv("REDIS_ADDRESS"),
		RedisPassword:  os.Getenv("REDIS_PASSWORD"),
		JWTSecret:      os.Getenv("JWT_SECRET"),
		TokenStore:     os.Getenv("TOKEN_STORE"),
		MTLSEnabled:    os.Getenv("MTLS_ENABLED") == "true", // Convert to bool
		ServerCertFile: os.Getenv("SERVER_CERT_FILE"),
		ServerKeyFile:  os.Getenv("SERVER_KEY_FILE"),
		CACertFile:     os.Getenv("CA_CERT_FILE"),
	}

	if cfg.TokenStore == "" {
		err := fmt.Errorf("TOKEN_STORE environment variable must be set ('redis' or 'inmemory')")
		log.Println(err.Error())
		return nil, err
	}

	if cfg.MTLSEnabled {
		if cfg.ServerCertFile == "" || cfg.ServerKeyFile == "" || cfg.CACertFile == "" {
			err := fmt.Errorf("MTLS_ENABLED is true, but SERVER_CERT_FILE, SERVER_KEY_FILE, and CA_CERT_FILE are not all set")
			log.Println(err.Error())
			return nil, err
		}
	}

	log.Println("Configuration loaded successfully.")
	return cfg, nil
}
