package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestInMemoryTokenRepository_RevokeToken(t *testing.T) {
	repo := NewInMemoryTokenRepository()
	ctx := context.Background()
	jti := "test-jti"
	expiration := 1 * time.Second

	err := repo.RevokeToken(ctx, jti, expiration)
	assert.NoError(t, err)

	// Check if the token is revoked immediately
	revoked, err := repo.IsTokenRevoked(ctx, jti)
	assert.NoError(t, err)
	assert.True(t, revoked)

	// Wait for the token to expire
	time.Sleep(expiration + 500*time.Millisecond) // Add some buffer

	// Check if the token is not revoked after expiration
	revoked, err = repo.IsTokenRevoked(ctx, jti)
	assert.NoError(t, err)
	assert.False(t, revoked)
}

func TestInMemoryTokenRepository_IsTokenRevoked(t *testing.T) {
	repo := NewInMemoryTokenRepository()
	ctx := context.Background()
	jti := "test-jti"
	expiration := 1 * time.Second

	// Token should not be revoked initially
	revoked, err := repo.IsTokenRevoked(ctx, jti)
	assert.NoError(t, err)
	assert.False(t, revoked)

	// Revoke the token
	err = repo.RevokeToken(ctx, jti, expiration)
	assert.NoError(t, err)

	// Token should be revoked now
	revoked, err = repo.IsTokenRevoked(ctx, jti)
	assert.NoError(t, err)
	assert.True(t, revoked)

	// Wait for the token to expire
	time.Sleep(expiration + 500*time.Millisecond) // Add some buffer

	// Token should not be revoked after expiration
	revoked, err = repo.IsTokenRevoked(ctx, jti)
	assert.NoError(t, err)
	assert.False(t, revoked)
}

func TestInMemoryTokenRepository_CreateRefreshToken(t *testing.T) {
	repo := NewInMemoryTokenRepository()
	ctx := context.Background()
	userID := uuid.New()
	token := "test-refresh-token"
	expiration := 1 * time.Hour // not really used, but for consistency

	err := repo.CreateRefreshToken(ctx, userID, token, expiration)
	assert.NoError(t, err)

	retrievedUserID, err := repo.GetRefreshToken(ctx, token)
	assert.NoError(t, err)
	assert.Equal(t, userID, retrievedUserID)
}

func TestInMemoryTokenRepository_GetRefreshToken(t *testing.T) {
	repo := NewInMemoryTokenRepository()
	ctx := context.Background()
	userID := uuid.New()
	token := "test-refresh-token"
	expiration := 1 * time.Hour // not really used, but for consistency

	// Token should not exist initially
	retrievedUserID, err := repo.GetRefreshToken(ctx, token)
	assert.Error(t, err)
	assert.Equal(t, uuid.Nil, retrievedUserID)

	// Create the token
	err = repo.CreateRefreshToken(ctx, userID, token, expiration)
	assert.NoError(t, err)

	// Token should exist now
	retrievedUserID, err = repo.GetRefreshToken(ctx, token)
	assert.NoError(t, err)
	assert.Equal(t, userID, retrievedUserID)
}

func TestInMemoryTokenRepository_RevokeRefreshToken(t *testing.T) {
	repo := NewInMemoryTokenRepository()
	ctx := context.Background()
	userID := uuid.New()
	token := "test-refresh-token"
	expiration := 1 * time.Hour // not really used, but for consistency

	// Create the token
	err := repo.CreateRefreshToken(ctx, userID, token, expiration)
	assert.NoError(t, err)

	// Revoke the token
	err = repo.RevokeRefreshToken(ctx, token)
	assert.NoError(t, err)

	// Token should not exist anymore
	retrievedUserID, err := repo.GetRefreshToken(ctx, token)
	assert.Error(t, err)
	assert.Equal(t, uuid.Nil, retrievedUserID)
}