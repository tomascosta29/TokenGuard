package app

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/tomascosta29/CostaAuth/internal/config"
)

// SetupTLSConfig creates a *tls.Config for mTLS.
func SetupTLSConfig(cfg *config.Config) (*tls.Config, error) {
	// Load server certificate and private key
	cert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server key pair: %w", err)
	}

	// Load CA certificate (for client certificate verification)
	caCert, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Create a certificate pool and add the CA certificate
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("failed to append CA certificate to pool")
	}

	// Create the TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},        // Server's certificate
		ClientAuth:   tls.RequireAndVerifyClientCert, // Require and verify client certs
		ClientCAs:    caCertPool,                     // CA pool for client verification
		MinVersion:   tls.VersionTLS12,               // Good practice: Enforce TLS 1.2 or higher
	}

	return tlsConfig, nil
}
