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
	"github.com/tomascosta29/CostaAuth/internal/app"
	"github.com/tomascosta29/CostaAuth/internal/config"
	"github.com/tomascosta29/CostaAuth/internal/handler"
	"github.com/tomascosta29/CostaAuth/internal/repository"
	"github.com/tomascosta29/CostaAuth/internal/service"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig(".env")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database connections
	userRepo, err := repository.NewSQLiteUserRepository("auth.db") // Use SQLite
	if err != nil {
		log.Fatal("failed to connect to SQLite", err)
	}

	// Choose TokenRepository implementation based on environment variable
	var tokenRepo repository.TokenRepository
	if cfg.TokenStore == "redis" {
		tokenRepo, err = repository.NewRedisTokenRepository(cfg.RedisAddress, cfg.RedisPassword)
		if err != nil {
			log.Fatal("Failed to create Redis client:", err)
		}
	} else if cfg.TokenStore == "inmemory" {
		tokenRepo = repository.NewInMemoryTokenRepository()
	} else {
		log.Fatalf("Invalid TOKEN_STORE environment variable: %s. Must be 'redis' or 'inmemory'.", cfg.TokenStore)
	}

	// Create the real bcryptPasswordChecker
	passwordChecker := service.NewBcryptPasswordChecker()

	// Initialize services
	userService := service.NewUserService(userRepo, passwordChecker)          // Inject passwordChecker
	tokenService := service.NewTokenService(tokenRepo, []byte(cfg.JWTSecret)) // Use selected tokenRepo

	// Initialize handlers
	authHandler := handler.NewAuthHandler(userService, tokenService)

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
		err = server.ListenAndServeTLS("", "") // Use ListenAndServeTLS
	} else {
		// Start without TLS
		err = server.ListenAndServe()
	}

	if err != http.ErrServerClosed {
		log.Fatalf("HTTP server ListenAndServe: %v", err)
	}

	<-idleConnsClosed
	log.Println("Server gracefully stopped")
}
