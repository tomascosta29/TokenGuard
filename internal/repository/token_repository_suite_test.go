package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func RunTokenRepositoryTests(t *testing.T, repo TokenRepository, cleanup func()) {
	t.Helper()
	defer cleanup()

	t.Run("TestRevokeAndCheckToken", func(t *testing.T) {
		ctx := context.Background()
		jti := "test-jti-1"
		expiration := 2 * time.Second

		// 1. Initially, token should not be revoked
		revoked, err := repo.IsTokenRevoked(ctx, jti)
		require.NoError(t, err)
		assert.False(t, revoked)

		// 2. Revoke the token
		err = repo.RevokeToken(ctx, uuid.New(), jti, expiration)
		require.NoError(t, err)

		// 3. Check if the token is revoked immediately
		revoked, err = repo.IsTokenRevoked(ctx, jti)
		require.NoError(t, err)
		assert.True(t, revoked)

		// 4. Wait for the token to expire from the revocation list
		time.Sleep(expiration + 500*time.Millisecond)

		// 5. Check if the token is no longer considered revoked
		revoked, err = repo.IsTokenRevoked(ctx, jti)
		require.NoError(t, err)
		assert.False(t, revoked)
	})

	t.Run("TestRefreshTokenLifecycle", func(t *testing.T) {
		ctx := context.Background()
		userID := uuid.New()
		token := "test-refresh-token-1"
		expiration := 1 * time.Hour // Expiration is long for refresh tokens

		// 1. Initially, refresh token should not exist
		retrievedUserID, err := repo.GetRefreshToken(ctx, token)
		require.Error(t, err) // Expect an error when token not found
		assert.Equal(t, uuid.Nil, retrievedUserID)

		// 2. Create the refresh token
		err = repo.CreateRefreshToken(ctx, userID, token, expiration)
		require.NoError(t, err)

		// 3. Retrieve the refresh token and verify user ID
		retrievedUserID, err = repo.GetRefreshToken(ctx, token)
		require.NoError(t, err)
		assert.Equal(t, userID, retrievedUserID)

		// 4. Revoke the refresh token
		err = repo.RevokeRefreshToken(ctx, token)
		require.NoError(t, err)

		// 5. Token should not exist anymore
		retrievedUserID, err = repo.GetRefreshToken(ctx, token)
		require.Error(t, err) // Expect an error after revocation
		assert.Equal(t, uuid.Nil, retrievedUserID)
	})

	t.Run("TestMultipleTokens", func(t *testing.T) {
		ctx := context.Background()
		jti1, jti2 := "multi-jti-1", "multi-jti-2"
		expiration := 2 * time.Second

		// Revoke jti1
		err := repo.RevokeToken(ctx, uuid.New(), jti1, expiration)
		require.NoError(t, err)

		// Check statuses
		revoked1, err := repo.IsTokenRevoked(ctx, jti1)
		require.NoError(t, err)
		assert.True(t, revoked1)

		revoked2, err := repo.IsTokenRevoked(ctx, jti2)
		require.NoError(t, err)
		assert.False(t, revoked2)
	})

	t.Run("TestRevokeUserTokens", func(t *testing.T) {
		ctx := context.Background()
		user1ID := uuid.New()
		user2ID := uuid.New()
		jti1 := "user1-jti"
		jti2 := "user2-jti"
		expiration := 1 * time.Hour

		// Revoke tokens for both users
		err := repo.RevokeToken(ctx, user1ID, jti1, expiration)
		require.NoError(t, err)
		err = repo.RevokeToken(ctx, user2ID, jti2, expiration)
		require.NoError(t, err)

		// Verify both are revoked
		revoked1, err := repo.IsTokenRevoked(ctx, jti1)
		require.NoError(t, err)
		assert.True(t, revoked1)
		revoked2, err := repo.IsTokenRevoked(ctx, jti2)
		require.NoError(t, err)
		assert.True(t, revoked2)

		// Revoke all tokens for user 1
		err = repo.RevokeUserTokens(ctx, user1ID)
		require.NoError(t, err)

		// Check that user 1's token is no longer revoked
		revoked1, err = repo.IsTokenRevoked(ctx, jti1)
		require.NoError(t, err)
		assert.False(t, revoked1)

		// Check that user 2's token is still revoked
		revoked2, err = repo.IsTokenRevoked(ctx, jti2)
		require.NoError(t, err)
		assert.True(t, revoked2)
	})
}
