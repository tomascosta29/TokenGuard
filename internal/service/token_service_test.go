// File: TokenGuard/./internal/service/token_service_test.go
package service

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// --- Mock TokenRepository ---

// MockTokenRepository is a mock implementation of the TokenRepository interface.
type MockTokenRepository struct {
	mock.Mock // Use testify/mock for easy mocking
}

// RevokeToken is the mock implementation for RevokeToken.
func (m *MockTokenRepository) RevokeToken(ctx context.Context, jti string, expiration time.Duration) error {
	args := m.Called(ctx, jti, expiration) // Record the call
	return args.Error(0)                   // Return configured error (or nil)
}

// IsTokenRevoked is the mock implementation for IsTokenRevoked.
func (m *MockTokenRepository) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	args := m.Called(ctx, jti)         // Record the call
	return args.Bool(0), args.Error(1) // Return configured values (bool and error)
}

// Mock for CreateRefreshToken
func (m *MockTokenRepository) CreateRefreshToken(ctx context.Context, userID uuid.UUID, token string, expiration time.Duration) error {
	args := m.Called(ctx, userID, token, expiration)
	return args.Error(0)
}

// Mock for GetRefreshToken
func (m *MockTokenRepository) GetRefreshToken(ctx context.Context, token string) (uuid.UUID, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

// Mock for RevokeRefreshToken
func (m *MockTokenRepository) RevokeRefreshToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// --- Test Cases ---

func TestTokenService_GenerateToken(t *testing.T) {
	mockRepo := new(MockTokenRepository)                             // Create an instance of our mock
	tokenService := NewTokenService(mockRepo, []byte("test-secret")) // Inject the mock
	ctx := context.Background()
	userID := uuid.New()

	tokenString, err := tokenService.GenerateToken(ctx, userID)

	assert.NoError(t, err)          // Assert no error during generation
	assert.NotEmpty(t, tokenString) // Assert token string is not empty

	// Basic parsing to check structure (optional, but good for sanity)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("test-secret"), nil // Provide the signing key
	})
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, userID.String(), claims["sub"]) // Check subject claim

	mockRepo.AssertExpectations(t) // Ensure mock was used as expected (it wasn't, but good practice)
}

func TestTokenService_ValidateToken_Valid(t *testing.T) {
	mockRepo := new(MockTokenRepository)
	tokenService := NewTokenService(mockRepo, []byte("test-secret"))
	ctx := context.Background()
	userID := uuid.New()

	// Generate a valid token (we'll use the *real* GenerateToken for this)
	validTokenString, err := tokenService.GenerateToken(ctx, userID)
	assert.NoError(t, err)

	// Configure the mock: IsTokenRevoked should return false (not revoked)
	mockRepo.On("IsTokenRevoked", ctx, mock.AnythingOfType("string")).Return(false, nil)

	// Call ValidateToken
	claims, err := tokenService.ValidateToken(ctx, validTokenString)

	// Assertions
	assert.NoError(t, err)                          // No error should occur
	assert.NotNil(t, claims)                        // Claims should be returned
	assert.Equal(t, userID.String(), claims["sub"]) // Check the subject

	mockRepo.AssertExpectations(t) // Verify mock interactions
}

func TestTokenService_ValidateToken_InvalidSignature(t *testing.T) {
	mockRepo := new(MockTokenRepository)
	tokenService := NewTokenService(mockRepo, []byte("test-secret"))
	ctx := context.Background()

	// Create a token with an *invalid* signature
	invalidClaims := jwt.MapClaims{
		"sub": "invalid-user",
		"exp": time.Now().Add(time.Hour).Unix(),
		"jti": uuid.New().String(),
	}
	invalidToken := jwt.NewWithClaims(jwt.SigningMethodHS256, invalidClaims)
	invalidTokenString, _ := invalidToken.SignedString([]byte("wrong-secret")) // WRONG SECRET!

	// No mock setup for IsTokenRevoked needed - it should *not* be called

	// Call ValidateToken
	_, err := tokenService.ValidateToken(ctx, invalidTokenString)

	// Assertions: We *expect* an error due to the invalid signature
	assert.Error(t, err)
	assert.ErrorIs(t, err, jwt.ErrSignatureInvalid) // Check for *specific* error

	mockRepo.AssertExpectations(t) // No calls expected, but good practice to include
}

func TestTokenService_ValidateToken_Expired(t *testing.T) {
	mockRepo := new(MockTokenRepository)
	tokenService := NewTokenService(mockRepo, []byte("test-secret"))
	ctx := context.Background()

	// Create an *expired* token
	expiredClaims := jwt.MapClaims{
		"sub": "some-user",
		"exp": time.Now().Add(-time.Hour).Unix(), // Expired one hour ago!
		"jti": uuid.New().String(),
	}
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	expiredTokenString, _ := expiredToken.SignedString([]byte("test-secret"))

	// No mock setup for IsTokenRevoked needed - it should *not* be called

	// Call ValidateToken
	_, err := tokenService.ValidateToken(ctx, expiredTokenString)

	// Assertions: We *expect* an error due to expiration
	assert.Error(t, err)
	assert.ErrorIs(t, err, jwt.ErrTokenExpired) // Check for *specific* error

	mockRepo.AssertExpectations(t)
}

func TestTokenService_ValidateToken_Revoked(t *testing.T) {
	mockRepo := new(MockTokenRepository)
	tokenService := NewTokenService(mockRepo, []byte("test-secret"))
	ctx := context.Background()
	userID := uuid.New() // Consistent user ID

	// Create a token that's otherwise valid, but we'll *pretend* it's revoked
	revokedJti := uuid.New().String() // The JTI we'll "revoke"
	claimsMap := jwt.MapClaims{
		"sub": userID.String(),                  // Use consistent user ID
		"exp": time.Now().Add(time.Hour).Unix(), // Not expired
		"jti": revokedJti,                       // Set the JTI
	}
	revokedToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsMap)
	revokedTokenString, _ := revokedToken.SignedString([]byte("test-secret"))

	// Configure the mock:  IsTokenRevoked *will* be called with the revoked JTI
	mockRepo.On("IsTokenRevoked", ctx, revokedJti).Return(true, nil)

	// Call ValidateToken
	_, err := tokenService.ValidateToken(ctx, revokedTokenString)

	// Assertions: We *expect* a "token has been revoked" error
	assert.Error(t, err)
	assert.EqualError(t, err, "token has been revoked") // Check for *specific* error

	mockRepo.AssertExpectations(t)
}
