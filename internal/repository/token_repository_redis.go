// File: /home/fcosta/CostaAuth/./internal/repository/token_repository_redis.go
package repository

import (
	"context"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
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
