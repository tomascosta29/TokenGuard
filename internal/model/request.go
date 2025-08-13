// File: TokenGuard/./internal/model/request.go
package model

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type AdminRevokeRequest struct {
	UserID string `json:"user_id"`
}
