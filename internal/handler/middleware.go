package handler

import (
	"log/slog"
	"net/http"

	"github.com/tomascosta29/TokenGuard/internal/service"
)

// AuthMiddleware creates a middleware that checks for a valid JWT.
func AuthMiddleware(tokenService service.TokenServiceInterface, logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info("AuthMiddleware: Incoming request")
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				respondWithError(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			tokenString, err := extractBearerToken(authHeader)
			if err != nil {
				logger.Warn("AuthMiddleware: Invalid auth header", "error", err)
				respondWithError(w, err.Error(), http.StatusUnauthorized)
				return
			}

			_, err = tokenService.ValidateToken(r.Context(), tokenString)
			if err != nil {
				logger.Warn("AuthMiddleware: Invalid token", "error", err)
				respondWithError(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			logger.Info("AuthMiddleware: Token is valid")
			next.ServeHTTP(w, r)
		})
	}
}
