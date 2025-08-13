package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/mail"

	"github.com/gorilla/mux"
	"github.com/tomascosta29/TokenGuard/internal/model"
	"github.com/tomascosta29/TokenGuard/internal/service"
)

type AuthHandler struct {
	userService  service.UserServiceInterface
	tokenService service.TokenServiceInterface
	logger       *slog.Logger
}

func NewAuthHandler(userService service.UserServiceInterface, tokenService service.TokenServiceInterface, logger *slog.Logger) *AuthHandler {
	return &AuthHandler{
		userService:  userService,
		tokenService: tokenService,
		logger:       logger,
	}
}

func (h *AuthHandler) RegisterRoutes(r *mux.Router) {
	// Create a subrouter for /v1 routes
	v1 := r.PathPrefix("/v1").Subrouter()

	// All auth routes will be under /v1
	authRouter := v1.PathPrefix("/auth").Subrouter()
	authRouter.HandleFunc("/register", h.RegisterHandler).Methods("POST")
	authRouter.HandleFunc("/login", h.LoginHandler).Methods("POST")
	authRouter.HandleFunc("/refresh", h.RefreshHandler).Methods("POST")
	authRouter.HandleFunc("/logout", h.LogoutHandler).Methods("POST")
	authRouter.HandleFunc("/validate", h.ValidateTokenHandler).Methods("GET")
}

func (h *AuthHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("RegisterHandler: Incoming request")
	var req model.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("RegisterHandler: Invalid request body", "error", err)
		respondWithError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Input Validation
	if req.Username == "" || req.Email == "" || req.Password == "" {
		respondWithError(w, "All fields are required", http.StatusBadRequest)
		return
	}

	// Username validation
	if err := validateUsername(req.Username); err != nil {
		respondWithError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Email validation
	if _, err := mail.ParseAddress(req.Email); err != nil {
		respondWithError(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	// Password validation
	if err := validatePasswordComplexity(req.Password); err != nil {
		respondWithError(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err := h.userService.RegisterUser(r.Context(), &req)
	if err != nil {
		h.logger.Error("RegisterHandler: Registration failed", "error", err)
		// Do not expose internal error message to the client
		respondWithError(w, "Registration failed", http.StatusBadRequest)
		return
	}

	respondWithJSON(w, http.StatusCreated, map[string]string{"message": "User registered successfully"})
	h.logger.Info("RegisterHandler: User registered successfully")
}

func (h *AuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("LoginHandler: Incoming request")
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("LoginHandler: Invalid request body", "error", err)
		respondWithError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		respondWithError(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	if err := validateUsername(req.Username); err != nil {
		respondWithError(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.userService.LoginUser(r.Context(), &req)
	if err != nil {
		h.logger.Warn("LoginHandler: Login failed", "error", err, "username", req.Username)
		respondWithError(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	token, err := h.tokenService.GenerateToken(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("LoginHandler: Failed to generate token", "error", err)
		respondWithError(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := h.tokenService.GenerateRefreshToken(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("LoginHandler: Failed to generate refresh token", "error", err)
		respondWithError(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"token": token, "refresh_token": refreshToken})
	h.logger.Info("LoginHandler: Login successful, token generated", "user_id", user.ID)
}

func (h *AuthHandler) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("RefreshHandler: Incoming request")
	var req model.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("RefreshHandler: Invalid request body", "error", err)
		respondWithError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	refreshToken := req.RefreshToken

	userID, err := h.tokenService.ValidateRefreshToken(r.Context(), refreshToken)
	if err != nil {
		h.logger.Warn("RefreshHandler: Invalid refresh token", "error", err)
		respondWithError(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	if err := h.tokenService.RevokeRefreshToken(r.Context(), refreshToken); err != nil {
		h.logger.Error("RefreshHandler: Failed to revoke refresh token", "error", err)
		respondWithError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	accessToken, err := h.tokenService.GenerateToken(r.Context(), userID)
	if err != nil {
		h.logger.Error("RefreshHandler: Failed to generate access token", "error", err)
		respondWithError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	newRefreshToken, err := h.tokenService.GenerateRefreshToken(r.Context(), userID)
	if err != nil {
		h.logger.Error("RefreshHandler: Failed to generate new refresh token", "error", err)
		respondWithError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"access_token": accessToken, "refresh_token": newRefreshToken})
	h.logger.Info("RefreshHandler: Access token generated successfully", "user_id", userID)
}

func (h *AuthHandler) ValidateTokenHandler(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("ValidateTokenHandler: Incoming request")
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		respondWithError(w, "Authorization header required", http.StatusUnauthorized)
		return
	}
	tokenString, err := extractBearerToken(authHeader)
	if err != nil {
		respondWithError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	claims, err := h.tokenService.ValidateToken(r.Context(), tokenString)
	if err != nil {
		h.logger.Warn("ValidateTokenHandler: Invalid token", "error", err)
		respondWithError(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	respondWithJSON(w, http.StatusOK, claims)
	h.logger.Info("ValidateTokenHandler: Token validated successfully")
}

func (h *AuthHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("LogoutHandler: Incoming request")
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		respondWithError(w, "Authorization header required", http.StatusUnauthorized)
		return
	}
	tokenString, err := extractBearerToken(authHeader)
	if err != nil {
		respondWithError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	err = h.tokenService.RevokeToken(r.Context(), tokenString)
	if err != nil {
		h.logger.Error("LogoutHandler: Could not log out", "error", err)
		respondWithError(w, "Could not log out", http.StatusUnauthorized)
		return
	}
	respondWithJSON(w, http.StatusOK, map[string]string{"message": "User logged out successfully"})
	h.logger.Info("LogoutHandler: Logged out successfully")
}
