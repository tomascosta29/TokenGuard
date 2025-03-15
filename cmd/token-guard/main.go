// File: /cmd/token-guard/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/tomascosta29/TokenGuard/internal/app"
	"github.com/tomascosta29/TokenGuard/internal/config"
	"github.com/tomascosta29/TokenGuard/internal/handler"
	"github.com/tomascosta29/TokenGuard/internal/repository"
	"github.com/tomascosta29/TokenGuard/internal/service"
)

func main() {
	log.Println("Starting TokenGuard service...")

	// Load configuration
	cfg, err := config.LoadConfig(".env")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Config loaded successfully. Port: %s, TokenStore: %s, MTLS: %t", cfg.Port, cfg.TokenStore, cfg.MTLSEnabled)

	// Initialize database connections
	userRepo, err := repository.NewSQLiteUserRepository("auth.db") // Use SQLite
	if err != nil {
		log.Fatal("failed to connect to SQLite", err)
	}
	log.Println("SQLite user repository initialized.")

	// Choose TokenRepository implementation based on environment variable
	var tokenRepo repository.TokenRepository
	if cfg.TokenStore == "redis" {
		tokenRepo, err = repository.NewRedisTokenRepository(cfg.RedisAddress, cfg.RedisPassword)
	} else if cfg.TokenStore == "inmemory" {
		tokenRepo = repository.NewInMemoryTokenRepository()
	}
	if err != nil {
		log.Fatal("Failed to create token repository:", err)
	} else if cfg.TokenStore == "inmemory" {
		log.Println("In-memory token repository initialized.")
	} else {
		log.Fatalf("Invalid TOKEN_STORE environment variable: %s. Must be 'redis' or 'inmemory'.", cfg.TokenStore)
	}

	// Create the real bcryptPasswordChecker
	passwordChecker := service.NewBcryptPasswordChecker()

	// Initialize services
	userService := service.NewUserService(userRepo, passwordChecker) // Inject passwordChecker
	log.Println("User service initialized.")

	tokenService := service.NewTokenService(tokenRepo, []byte(cfg.JWTSecret)) // Use selected tokenRepo
	log.Println("Token service initialized.")

	// Initialize handlers
	authHandler := handler.NewAuthHandler(userService, tokenService)
	log.Println("Auth handler initialized.")

	// Create router and register routes
	r := mux.NewRouter()
	authHandler.RegisterRoutes(r)

	// Create a server
	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// --- mTLS Setup (Conditional) ---
	if cfg.MTLSEnabled {
		tlsConfig, err := app.SetupTLSConfig(cfg)
		if err != nil {
			log.Fatal("Failed to setup TLS config:", err)
		}
		server.TLSConfig = tlsConfig
		log.Println("mTLS enabled and TLS config setup.")
	}

	// Graceful shutdown setup
	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		<-sigint

		// We received an interrupt signal, shut down.
		log.Println("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			// Error from closing listeners, or context timeout:
			log.Printf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	// Start the server (with or without TLS)
	fmt.Printf("Starting server on port %s (mTLS: %t)\n", cfg.Port, cfg.MTLSEnabled)
	if cfg.MTLSEnabled {
		// Start with TLS
		// Use ListenAndServeTLS with empty strings for cert and key,
		// because they are already loaded in server.TLSConfig
		// Use ListenAndServeTLS with empty strings for cert and key,
		// because they are already loaded in server.TLSConfig
		log.Printf("Starting server with TLS on port %s", cfg.Port)
		err = server.ListenAndServeTLS("", "") // Use ListenAndServeTLS
	} else {
		// Start without TLS
		log.Printf("Starting server without TLS on port %s", cfg.Port)
		err = server.ListenAndServe()
	}

	if err != http.ErrServerClosed {
		log.Fatalf("HTTP server ListenAndServe: %v", err)
	}

	<-idleConnsClosed
	log.Println("Server gracefully stopped")
}
