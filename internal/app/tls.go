// File: /home/fcosta/CostaAuth/./internal/app/tls.go
package app

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"

	"github.com/tomascosta29/CostaAuth/internal/config"
)

// SetupTLSConfig creates a *tls.Config for mTLS.
func SetupTLSConfig(cfg *config.Config) (*tls.Config, error) {
	log.Println("Setting up TLS config...")
	// Load server certificate and private key
	cert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
	if err != nil {
		log.Printf("Failed to load server key pair: %v", err)
		return nil, fmt.Errorf("failed to load server key pair: %w", err)
	}
	log.Println("Server certificate and key loaded.")

	// Load CA certificate (for client certificate verification)
	caCert, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		log.Printf("Failed to read CA certificate: %v", err)
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}
	log.Println("CA certificate loaded.")

	// Create a certificate pool and add the CA certificate
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		log.Println("Failed to append CA certificate to pool")
		return nil, fmt.Errorf("failed to append CA certificate to pool")
	}
	log.Println("CA certificate appended to pool.")

	// Create the TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},        // Server's certificate
		ClientAuth:   tls.RequireAndVerifyClientCert, // Require and verify client certs
		ClientCAs:    caCertPool,                     // CA pool for client verification
		MinVersion:   tls.VersionTLS12,               // Enforce TLS 1.2 or higher
	}

	log.Println("TLS config created successfully.")
	return tlsConfig, nil
}
