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
		Password: password,
		DB:       0,
	})

	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		log.Printf("NewRedisTokenRepository: Failed to ping Redis: %v", err)
		return nil, err
	}

	log.Println("NewRedisTokenRepository: Connected to Redis successfully.")
	return &RedisTokenRepository{client: client}, nil
}

func (r *RedisTokenRepository) RevokeToken(ctx context.Context, userID uuid.UUID, jti string, expiration time.Duration) error {
	log.Printf("RevokeToken: Revoking token with JTI %s for user %s", jti, userID)
	pipe := r.client.TxPipeline()

	// Add the token to the blacklist
	pipe.Set(ctx, jti, "revoked", expiration)

	// Add the token's JTI to the user's set of tokens
	userTokensKey := fmt.Sprintf("user:%s:tokens", userID.String())
	pipe.SAdd(ctx, userTokensKey, jti)
	pipe.Expire(ctx, userTokensKey, expiration) // Expire the set as well

	_, err := pipe.Exec(ctx)
	if err != nil {
		log.Printf("RevokeToken: Failed to revoke token with JTI %s: %v", jti, err)
		return err
	}

	log.Printf("RevokeToken: Token with JTI %s revoked successfully", jti)
	return nil
}

func (r *RedisTokenRepository) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	val, err := r.client.Get(ctx, jti).Result()
	if err == redis.Nil {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return val == "revoked", nil
}

func (r *RedisTokenRepository) RevokeUserTokens(ctx context.Context, userID uuid.UUID) error {
	log.Printf("RevokeUserTokens: Revoking all tokens for user %s", userID)
	userTokensKey := fmt.Sprintf("user:%s:tokens", userID.String())

	// Get all tokens for the user
	jtis, err := r.client.SMembers(ctx, userTokensKey).Result()
	if err != nil {
		return err
	}

	if len(jtis) == 0 {
		return nil // No tokens to revoke
	}

	// Delete all the user's tokens from the main blacklist
	pipe := r.client.TxPipeline()
	for _, jti := range jtis {
		pipe.Del(ctx, jti)
	}
	// Also delete the user's token set
	pipe.Del(ctx, userTokensKey)

	_, err = pipe.Exec(ctx)
	if err != nil {
		log.Printf("RevokeUserTokens: Failed to revoke tokens for user %s: %v", userID, err)
		return err
	}

	log.Printf("RevokeUserTokens: All tokens for user %s have been revoked", userID)
	return nil
}

func (r *RedisTokenRepository) CreateRefreshToken(ctx context.Context, userID uuid.UUID, token string, expiration time.Duration) error {
	key := fmt.Sprintf("refresh_token:%s", token)
	userIDStr := userID.String()
	err := r.client.Set(ctx, key, userIDStr, expiration).Err()
	if err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}
	return nil
}

func (r *RedisTokenRepository) GetRefreshToken(ctx context.Context, token string) (uuid.UUID, error) {
	key := fmt.Sprintf("refresh_token:%s", token)
	userIDStr, err := r.client.Get(ctx, key).Result()
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to get refresh token: %w", err)
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse user ID: %w", err)
	}
	return userID, nil
}

func (r *RedisTokenRepository) RevokeRefreshToken(ctx context.Context, token string) error {
	key := fmt.Sprintf("refresh_token:%s", token)
	err := r.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}
	return nil
}
