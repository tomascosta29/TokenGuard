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

type TokenServiceInterface interface {
	GenerateToken(ctx context.Context, userID uuid.UUID) (string, error)
	ValidateToken(ctx context.Context, tokenString string) (jwt.MapClaims, error)
	RevokeToken(ctx context.Context, tokenString string) error
	GenerateRefreshToken(ctx context.Context, userID uuid.UUID) (string, error)
	ValidateRefreshToken(ctx context.Context, refreshToken string) (uuid.UUID, error)
	RevokeRefreshToken(ctx context.Context, refreshToken string) error
	RevokeUserTokens(ctx context.Context, userID uuid.UUID) error
}

type TokenService struct {
	tokenRepo              repository.TokenRepository
	jwtSecret              []byte
	refreshTokenExpiration time.Duration
}

func NewTokenService(tokenRepo repository.TokenRepository, jwtSecret []byte) *TokenService {
	log.Println("NewTokenService: Creating new token service")
	return &TokenService{
		tokenRepo:              tokenRepo,
		jwtSecret:              jwtSecret,
		refreshTokenExpiration: time.Hour * 24 * 7,
	}
}

func (s *TokenService) GenerateToken(ctx context.Context, userID uuid.UUID) (string, error) {
	log.Printf("GenerateToken: Generating token for user ID %s", userID)
	claims := jwt.MapClaims{
		"sub": userID.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour * 1).Unix(),
		"jti": uuid.New().String(),
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
		jti, ok := claims["jti"].(string)
		if !ok {
			log.Println("ValidateToken: Invalid token - missing jti")
			return nil, fmt.Errorf("invalid token: missing jti")
		}
		isRevoked, err := s.tokenRepo.IsTokenRevoked(ctx, jti)
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
	claims, err := s.ValidateToken(ctx, tokenString)
	if err != nil {
		log.Printf("RevokeToken: Token validation failed: %v", err)
		return err
	}

	jti, ok := claims["jti"].(string)
	if !ok {
		log.Println("RevokeToken: Invalid token: missing jti")
		return fmt.Errorf("invalid token: missing jti")
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		log.Println("RevokeToken: Invalid token: missing sub")
		return fmt.Errorf("invalid token: missing sub")
	}
	userID, err := uuid.Parse(sub)
	if err != nil {
		log.Println("RevokeToken: Invalid token: invalid sub")
		return fmt.Errorf("invalid token: invalid sub")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		log.Println("RevokeToken: Invalid token: missing expiration")
		return fmt.Errorf("invalid token: missing expiration")
	}
	expirationTime := time.Unix(int64(exp), 0)
	durationUntilExpiration := time.Until(expirationTime)

	err = s.tokenRepo.RevokeToken(ctx, userID, jti, durationUntilExpiration)
	if err != nil {
		log.Printf("RevokeToken: Failed to revoke token in repository: %v", err)
		return err
	}

	log.Println("RevokeToken: Token revoked successfully")
	return nil
}

func (s *TokenService) RevokeUserTokens(ctx context.Context, userID uuid.UUID) error {
	log.Printf("RevokeUserTokens: Revoking all tokens for user %s", userID)
	err := s.tokenRepo.RevokeUserTokens(ctx, userID)
	if err != nil {
		log.Printf("RevokeUserTokens: Failed to revoke tokens for user %s: %v", userID, err)
		return err
	}
	log.Printf("RevokeUserTokens: All tokens for user %s have been revoked", userID)
	return nil
}

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

func (s *TokenService) ValidateRefreshToken(ctx context.Context, refreshToken string) (uuid.UUID, error) {
	userID, err := s.tokenRepo.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		log.Printf("ValidateRefreshToken: Refresh token validation failed: %v", err)
		return uuid.Nil, err
	}
	log.Println("ValidateRefreshToken: Refresh token is valid")
	return userID, nil
}

func (s *TokenService) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	err := s.tokenRepo.RevokeRefreshToken(ctx, refreshToken)
	if err != nil {
		log.Printf("RevokeRefreshToken: Failed to revoke refresh token: %v", err)
		return err
	}
	log.Println("RevokeRefreshToken: Refresh token revoked successfully")
	return nil
}
