// File: /home/fcosta/CostaAuth/./internal/repository/token_repository_redis.go
package repository

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
)

type RedisTokenRepository struct {
	client RedisClient
}

func NewRedisTokenRepository(address, password string) (*RedisTokenRepository, error) {
	log.Printf("NewRedisTokenRepository: Connecting to Redis at %s", address)
	client := redis.NewClient(&redis.Options{
		Addr:     address,
		Password: password, // No password set
		DB:       0,        // Use default DB
	})

	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		log.Printf("NewRedisTokenRepository: Failed to ping Redis: %v", err)
		return nil, err
	}

	log.Println("NewRedisTokenRepository: Connected to Redis successfully.")
	return &RedisTokenRepository{client: client}, nil
}

func (r *RedisTokenRepository) RevokeToken(ctx context.Context, jti string, expiration time.Duration) error {
	log.Printf("RevokeToken: Revoking token with JTI %s", jti)
	err := r.client.Set(ctx, jti, "revoked", expiration).Err() // key, value, expiration
	if err != nil {
		log.Printf("RevokeToken: Failed to revoke token with JTI %s: %v", jti, err)
		return err
	}
	log.Printf("RevokeToken: Token with JTI %s revoked successfully", jti)
	return nil
}

func (r *RedisTokenRepository) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	log.Printf("IsTokenRevoked: Checking if token with JTI %s is revoked", jti)
	val, err := r.client.Get(ctx, jti).Result()
	if err == redis.Nil { // key not found == not blacklisted
		log.Printf("IsTokenRevoked: Token with JTI %s is not revoked", jti)
		return false, nil
	} else if err != nil {
		log.Printf("IsTokenRevoked: Error checking revocation status for JTI %s: %v", jti, err)
		return false, err
	}
	// If the key exists, the token is revoked
	isRevoked := val == "revoked"
	log.Printf("IsTokenRevoked: Token with JTI %s is revoked: %t", jti, isRevoked)
	return isRevoked, nil
}

// CreateRefreshToken stores the refresh token in Redis, associated with the user ID.
func (r *RedisTokenRepository) CreateRefreshToken(ctx context.Context, userID uuid.UUID, token string, expiration time.Duration) error {
	key := fmt.Sprintf("refresh_token:%s", token)
	userIDStr := userID.String()

	err := r.client.Set(ctx, key, userIDStr, expiration).Err()
	if err != nil {
		log.Printf("CreateRefreshToken: Failed to store refresh token: %v", err)
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	log.Printf("CreateRefreshToken: Refresh token stored successfully for user %s", userID)
	return nil
}

// GetRefreshToken retrieves the user ID associated with the refresh token from Redis.
func (r *RedisTokenRepository) GetRefreshToken(ctx context.Context, token string) (uuid.UUID, error) {
	key := fmt.Sprintf("refresh_token:%s", token)

	userIDStr, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		log.Println("GetRefreshToken: Refresh token not found")
		return uuid.Nil, fmt.Errorf("refresh token not found")
	} else if err != nil {
		log.Printf("GetRefreshToken: Failed to get refresh token: %v", err)
		return uuid.Nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Printf("GetRefreshToken: Failed to parse user ID: %v", err)
		return uuid.Nil, fmt.Errorf("failed to parse user ID: %w", err)
	}

	log.Printf("GetRefreshToken: User ID %s retrieved successfully for refresh token", userID)
	return userID, nil
}

// RevokeRefreshToken removes the refresh token from Redis.
func (r *RedisTokenRepository) RevokeRefreshToken(ctx context.Context, token string) error {
	key := fmt.Sprintf("refresh_token:%s", token)

	err := r.client.Del(ctx, key).Err()
	if err != nil {
		log.Printf("RevokeRefreshToken: Failed to revoke refresh token: %v", err)
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	log.Printf("RevokeRefreshToken: Refresh token revoked successfully")
	return nil
}
