// File: /home/fcosta/CostaAuth/./internal/repository/token_repository_redis_test.go
package repository

import (
	"context"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
)

// Mock Redis for testing (can also use a real Redis instance if available)
type MockRedisClient struct {
	data map[string]string
}

func (m *MockRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	if m.data == nil {
		m.data = make(map[string]string)
	}
	m.data[key] = value.(string) // Simple mock, assuming string values
	// Simulate expiration (simplified)
	if expiration > 0 {
		time.AfterFunc(expiration, func() {
			delete(m.data, key)
		})
	}
	return redis.NewStatusResult("", nil) // No error in mock
}

func (m *MockRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	if m.data == nil {
		return redis.NewStringResult("", redis.Nil) // Key not found
	}
	val, ok := m.data[key]
	if !ok {
		return redis.NewStringResult("", redis.Nil)
	}
	return redis.NewStringResult(val, nil)
}

func (m *MockRedisClient) Ping(ctx context.Context) *redis.StatusCmd {
	return redis.NewStatusResult("PONG", nil) // No error in mock
}

func TestRedisTokenRepository_RevokeToken(t *testing.T) {
	mockClient := &MockRedisClient{}
	repo := &RedisTokenRepository{client: mockClient} // Use the mock
	ctx := context.Background()

	jti := "test-jti"
	expiration := time.Minute

	err := repo.RevokeToken(ctx, jti, expiration)
	assert.NoError(t, err)

	// Check if the token is revoked (using the mock)
	isRevoked, err := repo.IsTokenRevoked(ctx, jti)
	assert.NoError(t, err)
	assert.True(t, isRevoked)

	// Wait longer than expiration
	time.Sleep(expiration + time.Millisecond*100) // add margin
	isRevoked, err = repo.IsTokenRevoked(ctx, jti)
	assert.NoError(t, err)
	assert.False(t, isRevoked, "token should be expired")
}

func TestRedisTokenRepository_IsTokenRevoked(t *testing.T) {
	mockClient := &MockRedisClient{}
	repo := &RedisTokenRepository{client: mockClient}
	ctx := context.Background()

	jti := "another-test-jti"

	// Initially, the token should not be revoked
	isRevoked, err := repo.IsTokenRevoked(ctx, jti)
	assert.NoError(t, err)
	assert.False(t, isRevoked)

	// Revoke the token
	err = repo.RevokeToken(ctx, jti, time.Minute)
	assert.NoError(t, err)

	// Now it should be revoked
	isRevoked, err = repo.IsTokenRevoked(ctx, jti)
	assert.NoError(t, err)
	assert.True(t, isRevoked)
}

//For real integration test, you can use this (commented out) and replace MockRedisClient with a real client.
/*
func TestRedisTokenRepository_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	repo, err := NewRedisTokenRepository("localhost:6379", "") // Use a real Redis
    require.NoError(t, err)
	ctx := context.Background()

	jti := "integration-test-jti"
	expiration := time.Minute

	err = repo.RevokeToken(ctx, jti, expiration)
	assert.NoError(t, err)

	isRevoked, err := repo.IsTokenRevoked(ctx, jti)
	assert.NoError(t, err)
	assert.True(t, isRevoked)

    time.Sleep(expiration + time.Millisecond*100)
    isRevoked, err = repo.IsTokenRevoked(ctx, jti)
    assert.NoError(t, err)
    assert.False(t, isRevoked)
}
*/
