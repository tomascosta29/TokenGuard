package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/tomascosta29/CostaAuth/internal/model"
	"github.com/tomascosta29/CostaAuth/internal/service"
)

type AuthHandler struct {
	userService  service.UserServiceInterface  // Use the interface
	tokenService service.TokenServiceInterface // Use the interface
}

func NewAuthHandler(userService service.UserServiceInterface, tokenService service.TokenServiceInterface) *AuthHandler {
	return &AuthHandler{userService: userService, tokenService: tokenService}
}

func (h *AuthHandler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/auth/register", h.RegisterHandler).Methods("POST")
	r.HandleFunc("/auth/login", h.LoginHandler).Methods("POST")
	r.HandleFunc("/auth/refresh", h.RefreshHandler).Methods("POST")
	r.HandleFunc("/auth/logout", h.LogoutHandler).Methods("POST")
	r.HandleFunc("/auth/validate", h.ValidateTokenHandler).Methods("GET")
}

func (h *AuthHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req model.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	_, err := h.userService.RegisterUser(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest) // Or a different status code
		return
	}

	w.WriteHeader(http.StatusCreated) // 201 Created
	fmt.Fprintln(w, "User registered successfully")
}

func (h *AuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := h.userService.LoginUser(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	token, err := h.tokenService.GenerateToken(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func (h *AuthHandler) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	var req model.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// in a real-world scenario you would retrieve the refresh token claims
	// here for simplicity's sake, and since its a mock, its not really implemented
	// so we just return a new token.
	// Refresh Token logic would include validating the Refresh token,
	// checking if its blacklisted, and issueing a new access token
	// (and potentially, a new refresh token)

	userID, _ := uuid.NewUUID() // Normally, extract user ID from refresh token
	accessToken, err := h.tokenService.GenerateToken(r.Context(), userID)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"access_token": accessToken})
}

func (h *AuthHandler) ValidateTokenHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}
	// JWT has "Bearer " prefix
	tokenString := authHeader[len("Bearer "):]

	claims, err := h.tokenService.ValidateToken(r.Context(), tokenString)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims)
}

func (h *AuthHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}
	tokenString := authHeader[len("Bearer "):]
	err := h.tokenService.RevokeToken(r.Context(), tokenString)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not log out: %v", err), http.StatusUnauthorized)
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Logged out successfully")
}
