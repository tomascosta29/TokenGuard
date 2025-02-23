// File: /home/fcosta/CostaAuth/./internal/model/user.go
package model

import "github.com/google/uuid"

type User struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"` // Don't serialize the password hash
	CreatedAt    int64     `json:"created_at"`
	UpdatedAt    int64     `json:"updated_at"`
	IsActive     bool      `json:"is_active"`
}
