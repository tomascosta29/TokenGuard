package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/mail"

	"github.com/gorilla/mux"
	"github.com/tomascosta29/TokenGuard/internal/model"
	"github.com/tomascosta29/TokenGuard/internal/service"
)

type AuthHandler struct {
	userService  service.UserServiceInterface
	tokenService service.TokenServiceInterface
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
	log.Println("RegisterHandler: Incoming request")
	var req model.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("RegisterHandler: Invalid request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Input Validation
	if req.Username == "" || req.Email == "" || req.Password == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		return
	}

	// Username validation
	if err := validateUsername(req.Username); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Email validation (basic check)
	// not sure if it checks syntax only, or also if domain exist etc but i guess it's fine either way. Topic will be rivisited during securty audit
	if _, err := mail.ParseAddress(req.Email); err != nil {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	// Password validation (complexity check)
	if err := validatePasswordComplexity(req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err := h.userService.RegisterUser(r.Context(), &req)
	if err != nil {
		log.Printf("RegisterHandler: Registration failed: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest) // Or a different status code
		return
	}

	w.Header().Set("Content-Type", "application/json")                                      // Set Content-Type
	w.WriteHeader(http.StatusCreated)                                                       // 201 Created
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"}) // JSON response
	log.Println("RegisterHandler: User registered successfully")
}

func (h *AuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("LoginHandler: Incoming request")
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("LoginHandler: Invalid request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Validate username format, same as in registration
	if err := validateUsername(req.Username); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.userService.LoginUser(r.Context(), &req)
	if err != nil {
		log.Printf("LoginHandler: Login failed: %v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	token, err := h.tokenService.GenerateToken(r.Context(), user.ID)
	if err != nil {
		log.Printf("LoginHandler: Failed to generate token: %v", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := h.tokenService.GenerateRefreshToken(r.Context(), user.ID)
	if err != nil {
		log.Printf("LoginHandler: Failed to generate refresh token: %v", err)
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token, "refresh_token": refreshToken})
	log.Println("LoginHandler: Login successful, token generated")
}

func (h *AuthHandler) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("RefreshHandler: Incoming request")
	var req model.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("RefreshHandler: Invalid request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	refreshToken := req.RefreshToken

	// Validate the refresh token
	userID, err := h.tokenService.ValidateRefreshToken(r.Context(), refreshToken)
	if err != nil {
		log.Printf("RefreshHandler: Invalid refresh token: %v", err)
		// Use a structured error response for consistency
		w.Header().Set("Content-Type", "application/json") // Set Content-Type *before* writing the status
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid refresh token"})
		return
	}

	// Revoke the used refresh token
	err = h.tokenService.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		log.Printf("RefreshHandler: Failed to revoke refresh token: %v", err)
		http.Error(w, "Failed to revoke refresh token", http.StatusInternalServerError)
		return
	}

	// Generate a new access token
	accessToken, err := h.tokenService.GenerateToken(r.Context(), userID)
	if err != nil {
		log.Printf("RefreshHandler: Failed to generate access token: %v", err)
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	// Generate a new refresh token (for refresh token rotation)
	newRefreshToken, err := h.tokenService.GenerateRefreshToken(r.Context(), userID)
	if err != nil {
		log.Printf("RefreshHandler: Failed to generate new refresh token: %v", err)
		http.Error(w, "Failed to generate new refresh token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"access_token": accessToken, "refresh_token": newRefreshToken})
	log.Println("RefreshHandler: Access token generated successfully")
}

func (h *AuthHandler) ValidateTokenHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("ValidateTokenHandler: Incoming request")
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		log.Println("ValidateTokenHandler: Authorization header required")
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}
	tokenString, err := extractBearerToken(authHeader)
	if err != nil {
		log.Printf("ValidateTokenHandler: %v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	claims, err := h.tokenService.ValidateToken(r.Context(), tokenString)
	if err != nil {
		log.Printf("ValidateTokenHandler: Invalid token: %v", err)
		http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims)
	log.Println("ValidateTokenHandler: Token validated successfully")
}

func (h *AuthHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("LogoutHandler: Incoming request")
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		log.Println("LogoutHandler: Authorization header required")
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}
	tokenString, err := extractBearerToken(authHeader)
	if err != nil {
		log.Printf("LogoutHandler: %v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	err = h.tokenService.RevokeToken(r.Context(), tokenString)
	if err != nil {
		log.Printf("LogoutHandler: Could not log out: %v", err)
		http.Error(w, fmt.Sprintf("could not log out: %v", err), http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json") // Set Content-Type
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User logged out successfully"}) // JSON response
	log.Println("LogoutHandler: Logged out successfully")
}

// validatePasswordComplexity checks if a password meets complexity requirements.
func validatePasswordComplexity(password string) error {
	minLength := 8
	hasUpper := false
	hasLower := false
	hasNumber := false
	hasSpecial := false

	if len(password) < minLength {
		return fmt.Errorf("password must be at least %d characters long", minLength)
	}

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasNumber = true
		case isSpecialCharacter(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return fmt.Errorf("password must contain at least one number")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// isSpecialCharacter checks if a character is a special character
func isSpecialCharacter(char rune) bool {
	specialChars := "!\"#$%&'()*+,-./:;<=>?@[]^_{|}~"
	for _, specialChar := range specialChars {
		if char == specialChar {
			return true
		}
	}
	return false
}
