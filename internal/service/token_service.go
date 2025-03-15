// File: TokenGuard/./internal/service/token_service.go
package service

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tomascosta29/TokenGuard/internal/repository"
)

// Add this interface! Crucial for mocking the service for handler testing.
type TokenServiceInterface interface {
	GenerateToken(ctx context.Context, userID uuid.UUID) (string, error)
	ValidateToken(ctx context.Context, tokenString string) (jwt.MapClaims, error)
	RevokeToken(ctx context.Context, tokenString string) error
	GenerateRefreshToken(ctx context.Context, userID uuid.UUID) (string, error)       // New Function
	ValidateRefreshToken(ctx context.Context, refreshToken string) (uuid.UUID, error) // New Function
	RevokeRefreshToken(ctx context.Context, refreshToken string) error                // New Function
}

type TokenService struct {
	tokenRepo              repository.TokenRepository
	jwtSecret              []byte
	refreshTokenExpiration time.Duration // Define refresh token expiration
}

func NewTokenService(tokenRepo repository.TokenRepository, jwtSecret []byte) *TokenService {
	log.Println("NewTokenService: Creating new token service")
	return &TokenService{
		tokenRepo:              tokenRepo,
		jwtSecret:              jwtSecret,
		refreshTokenExpiration: time.Hour * 24 * 7, // 7 days expiration for refresh tokens
	}
}

// GenerateToken generates a new JWT
func (s *TokenService) GenerateToken(ctx context.Context, userID uuid.UUID) (string, error) {
	log.Printf("GenerateToken: Generating token for user ID %s", userID)
	// Create the Claims
	claims := jwt.MapClaims{
		"sub": userID.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour * 1).Unix(), // 1-hour expiration
		"jti": uuid.New().String(),                  // Unique JWT ID
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(s.jwtSecret)
	if err != nil {
		log.Printf("GenerateToken: Failed to sign token: %v", err)
		return "", err
	}
	log.Printf("GenerateToken: Token generated successfully for user ID %s", userID)
	return ss, err
}

// ValidateToken validates a JWT and returns the claims if valid
func (s *TokenService) ValidateToken(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	log.Println("ValidateToken: Validating token")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		log.Printf("ValidateToken: Token parsing failed: %v", err)
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Check if the token is revoked
		jti, ok := claims["jti"].(string) // extract jti
		if !ok {
			log.Println("ValidateToken: Invalid token - missing jti")
			return nil, fmt.Errorf("invalid token: missing jti")
		}
		isRevoked, err := s.tokenRepo.IsTokenRevoked(ctx, jti) // check if blacklisted
		if err != nil {
			log.Printf("ValidateToken: Error checking token revocation status: %v", err)
			return nil, fmt.Errorf("error checking token revocation status: %v", err)
		}
		if isRevoked {
			log.Println("ValidateToken: Token has been revoked")
			return nil, fmt.Errorf("token has been revoked")
		}

		log.Println("ValidateToken: Token is valid")
		return claims, nil
	} else {
		log.Println("ValidateToken: Invalid token")
		return nil, fmt.Errorf("invalid token")
	}
}

func (s *TokenService) RevokeToken(ctx context.Context, tokenString string) error {
	log.Println("RevokeToken: Revoking token")
	claims, err := s.ValidateToken(ctx, tokenString) // validate first
	if err != nil {
		log.Printf("RevokeToken: Token validation failed: %v", err)
		return err
	}
	jti, ok := claims["jti"].(string) // extract jti
	if !ok {
		log.Println("RevokeToken: Invalid token: missing jti")
		return fmt.Errorf("invalid token: missing jti")
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		log.Println("RevokeToken: Invalid token: missing expiration")
		return fmt.Errorf("invalid token: missing expiration")
	}
	expirationTime := time.Unix(int64(exp), 0)
	durationUntilExpiration := time.Until(expirationTime)

	err = s.tokenRepo.RevokeToken(ctx, jti, durationUntilExpiration)
	if err != nil {
		log.Printf("RevokeToken: Failed to revoke token in repository: %v", err)
		return err
	}

	log.Println("RevokeToken: Token revoked successfully")
	return nil
}

// GenerateRefreshToken generates a new refresh token
func (s *TokenService) GenerateRefreshToken(ctx context.Context, userID uuid.UUID) (string, error) {
	refreshToken := uuid.New().String()
	err := s.tokenRepo.CreateRefreshToken(ctx, userID, refreshToken, s.refreshTokenExpiration)
	if err != nil {
		log.Printf("GenerateRefreshToken: Failed to store refresh token: %v", err)
		return "", err
	}
	log.Printf("GenerateRefreshToken: Refresh token generated successfully for user ID %s", userID)
	return refreshToken, nil
}

// ValidateRefreshToken validates a refresh token
func (s *TokenService) ValidateRefreshToken(ctx context.Context, refreshToken string) (uuid.UUID, error) {
	userID, err := s.tokenRepo.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		log.Printf("ValidateRefreshToken: Refresh token validation failed: %v", err)
		return uuid.Nil, err
	}
	log.Println("ValidateRefreshToken: Refresh token is valid")
	return userID, nil
}

// RevokeRefreshToken revokes a refresh token
func (s *TokenService) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	err := s.tokenRepo.RevokeRefreshToken(ctx, refreshToken)
	if err != nil {
		log.Printf("RevokeRefreshToken: Failed to revoke refresh token: %v", err)
		return err
	}
	log.Println("RevokeRefreshToken: Refresh token revoked successfully")
	return nil
}
