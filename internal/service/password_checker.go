// File: /home/fcosta/CostaAuth/./internal/service/password_checker.go
package service

import "golang.org/x/crypto/bcrypt"

// PasswordChecker interface defines the contract for password checking.
type PasswordChecker interface {
	CheckPasswordHash(password, hash string) bool
}

// bcryptPasswordChecker is a concrete implementation using bcrypt.
type bcryptPasswordChecker struct{}

// CheckPasswordHash implements the PasswordChecker interface using bcrypt.
func (b *bcryptPasswordChecker) CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// NewBcryptPasswordChecker creates a new instance of bcryptPasswordChecker.
func NewBcryptPasswordChecker() *bcryptPasswordChecker {
	return &bcryptPasswordChecker{}
}
