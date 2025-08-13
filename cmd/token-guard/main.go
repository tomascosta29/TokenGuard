// File: /cmd/token-guard/main.go
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/time/rate"
	"github.com/tomascosta29/TokenGuard/internal/app"
	"github.com/tomascosta29/TokenGuard/internal/config"
	"github.com/tomascosta29/TokenGuard/internal/handler"
	"github.com/tomascosta29/TokenGuard/internal/repository"
	"github.com/tomascosta29/TokenGuard/internal/service"
)

func main() {
	// Initialize structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	logger.Info("Starting TokenGuard service...")

	// Load configuration
	cfg, err := config.LoadConfig(".env")
	if err != nil {
		logger.Error("Failed to load config", "error", err)
		os.Exit(1)
	}
	logger.Info("Config loaded successfully", "port", cfg.Port, "token_store", cfg.TokenStore, "mtls", cfg.MTLSEnabled)

	// Initialize database connections
	userRepo, err := repository.NewSQLiteUserRepository(cfg.DBPath) // Use configured DB path
	if err != nil {
		logger.Error("failed to connect to SQLite", "error", err)
		os.Exit(1)
	}
	logger.Info("SQLite user repository initialized.")

	// Choose TokenRepository implementation based on environment variable
	var tokenRepo repository.TokenRepository
	switch cfg.TokenStore {
	case "redis":
		tokenRepo, err = repository.NewRedisTokenRepository(cfg.RedisAddress, cfg.RedisPassword)
		if err != nil {
			logger.Error("Failed to create token repository", "error", err)
			os.Exit(1)
		}
		logger.Info("Redis token repository initialized.")
	case "inmemory":
		tokenRepo = repository.NewInMemoryTokenRepository()
		logger.Info("In-memory token repository initialized.")
	default:
		logger.Error("Invalid TOKEN_STORE environment variable", "token_store", cfg.TokenStore)
		os.Exit(1)
	}

	// Create the real bcryptPasswordChecker
	passwordChecker := service.NewBcryptPasswordChecker()

	// Initialize services
	userService := service.NewUserService(userRepo, passwordChecker) // Inject passwordChecker
	logger.Info("User service initialized.")

	tokenService := service.NewTokenService(tokenRepo, []byte(cfg.JWTSecret)) // Use selected tokenRepo
	logger.Info("Token service initialized.")

	// Initialize handlers
	authHandler := handler.NewAuthHandler(userService, tokenService, logger)
	logger.Info("Auth handler initialized.")

	// Create router and register routes
	r := mux.NewRouter()

	// Initialize the rate limiter
	if cfg.RateLimiterEnabled {
		slog.Info("Rate limiter enabled", "limit", cfg.RateLimit, "burst", cfg.RateBurst)
		limiter := handler.NewIPRateLimiter(rate.Limit(cfg.RateLimit), cfg.RateBurst)
		r.Use(handler.RateLimitMiddleware(limiter))
	}

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
			logger.Error("Failed to setup TLS config", "error", err)
			os.Exit(1)
		}
		server.TLSConfig = tlsConfig
		logger.Info("mTLS enabled and TLS config setup.")
	}

	// Graceful shutdown setup
	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		<-sigint

		// We received an interrupt signal, shut down.
		logger.Info("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			// Error from closing listeners, or context timeout:
			logger.Error("HTTP server Shutdown", "error", err)
		}
		close(idleConnsClosed)
	}()

	// Start the server (with or without TLS)
	logger.Info("Starting server", "port", cfg.Port, "mTLS", cfg.MTLSEnabled)
	if cfg.MTLSEnabled {
		// Start with TLS
		// Use ListenAndServeTLS with empty strings for cert and key,
		// because they are already loaded in server.TLSConfig
		logger.Info("Starting server with TLS", "port", cfg.Port)
		err = server.ListenAndServeTLS("", "") // Use ListenAndServeTLS
	} else {
		// Start without TLS
		logger.Info("Starting server without TLS", "port", cfg.Port)
		err = server.ListenAndServe()
	}

	if err != http.ErrServerClosed {
		logger.Error("HTTP server ListenAndServe", "error", err)
		os.Exit(1)
	}

	<-idleConnsClosed
	logger.Info("Server gracefully stopped")
}
