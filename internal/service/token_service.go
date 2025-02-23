package service

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tomascosta29/CostaAuth/internal/repository"
)

// Add this interface! Crucial for mocking the service for handler testing.
type TokenServiceInterface interface {
	GenerateToken(ctx context.Context, userID uuid.UUID) (string, error)
	ValidateToken(ctx context.Context, tokenString string) (jwt.MapClaims, error)
	RevokeToken(ctx context.Context, tokenString string) error
}

type TokenService struct {
	tokenRepo repository.TokenRepository
	jwtSecret []byte
}

func NewTokenService(tokenRepo repository.TokenRepository, jwtSecret []byte) *TokenService {
	return &TokenService{tokenRepo: tokenRepo, jwtSecret: jwtSecret}
}

// GenerateToken generates a new JWT
func (s *TokenService) GenerateToken(ctx context.Context, userID uuid.UUID) (string, error) {
	// Create the Claims
	claims := jwt.MapClaims{
		"sub": userID.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour * 1).Unix(), // 1-hour expiration
		"jti": uuid.New().String(),                  // Unique JWT ID
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(s.jwtSecret)
	return ss, err
}

// ValidateToken validates a JWT and returns the claims if valid
func (s *TokenService) ValidateToken(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Check if the token is revoked
		jti, ok := claims["jti"].(string) // extract jti
		if !ok {
			return nil, fmt.Errorf("invalid token: missing jti")
		}
		isRevoked, err := s.tokenRepo.IsTokenRevoked(ctx, jti) // check if blacklisted
		if err != nil {
			return nil, fmt.Errorf("error checking token revocation status: %v", err)
		}
		if isRevoked {
			return nil, fmt.Errorf("token has been revoked")
		}

		return claims, nil
	} else {
		return nil, fmt.Errorf("invalid token")
	}
}

func (s *TokenService) RevokeToken(ctx context.Context, tokenString string) error {
	claims, err := s.ValidateToken(ctx, tokenString) // validate first
	if err != nil {
		return err
	}
	jti, ok := claims["jti"].(string) // extract jti
	if !ok {
		return fmt.Errorf("invalid token: missing jti")
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("invalid token: missing expiration")
	}
	expirationTime := time.Unix(int64(exp), 0)
	durationUntilExpiration := time.Until(expirationTime)

	return s.tokenRepo.RevokeToken(ctx, jti, durationUntilExpiration)
}
