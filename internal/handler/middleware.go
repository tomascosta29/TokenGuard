package handler

import (
	"fmt"
	"net/http"

	"github.com/tomascosta29/CostaAuth/internal/service"
)

// AuthMiddleware is a middleware function that checks for a valid JWT
func AuthMiddleware(tokenService *service.TokenService) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			// JWT has "Bearer " prefix
			tokenString := authHeader[len("Bearer "):]

			_, err := tokenService.ValidateToken(r.Context(), tokenString)
			if err != nil {
				http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
				return
			}

			// Token is valid, proceed to the next handler
			next.ServeHTTP(w, r)
		})
	}
}
