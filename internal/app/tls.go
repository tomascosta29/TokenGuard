// File: TokenGuard/./internal/app/tls.go
package app

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"

	"github.com/tomascosta29/TokenGuard/internal/config"
)

// SetupTLSConfig creates a *tls.Config for mTLS.
func SetupTLSConfig(cfg *config.Config) (*tls.Config, error) {
	slog.Info("Setting up TLS config...")
	// Load server certificate and private key
	cert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
	if err != nil {
		slog.Error("Failed to load server key pair", "error", err)
		return nil, fmt.Errorf("failed to load server key pair: %w", err)
	}
	slog.Info("Server certificate and key loaded.")

	// Load CA certificate (for client certificate verification)
	caCert, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		slog.Error("Failed to read CA certificate", "error", err)
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}
	slog.Info("CA certificate loaded.")

	// Create a certificate pool and add the CA certificate
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		slog.Error("Failed to append CA certificate to pool")
		return nil, fmt.Errorf("failed to append CA certificate to pool")
	}
	slog.Info("CA certificate appended to pool.")

	// Create the TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},        // Server's certificate
		ClientAuth:   tls.RequireAndVerifyClientCert, // Require and verify client certs
		ClientCAs:    caCertPool,                     // CA pool for client verification
		MinVersion:   tls.VersionTLS12,               // Enforce TLS 1.2 or higher
	}

	slog.Info("TLS config created successfully.")
	return tlsConfig, nil
}
