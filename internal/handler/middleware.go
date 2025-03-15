// File: TokenGuard/./internal/handler/middleware.go
package handler

import (
	"fmt"
	"log"
	"net/http"

	"github.com/tomascosta29/TokenGuard/internal/service"
)

// AuthMiddleware is a middleware function that checks for a valid JWT
func AuthMiddleware(tokenService *service.TokenService) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Println("AuthMiddleware: Incoming request")
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				log.Println("AuthMiddleware: Authorization header required")
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			// JWT has "Bearer " prefix
			tokenString := authHeader[len("Bearer "):]

			_, err := tokenService.ValidateToken(r.Context(), tokenString)
			if err != nil {
				log.Printf("AuthMiddleware: Invalid token: %v", err)
				http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
				return
			}

			// Token is valid, proceed to the next handler
			log.Println("AuthMiddleware: Token is valid")
			next.ServeHTTP(w, r)
		})
	}
}
