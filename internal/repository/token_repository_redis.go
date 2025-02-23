package repository

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
)

type RedisTokenRepository struct {
	client RedisClient
}

func NewRedisTokenRepository(address, password string) (*RedisTokenRepository, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     address,
		Password: password, // No password set
		DB:       0,        // Use default DB
	})

	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		return nil, err
	}

	return &RedisTokenRepository{client: client}, nil
}

func (r *RedisTokenRepository) RevokeToken(ctx context.Context, jti string, expiration time.Duration) error {
	return r.client.Set(ctx, jti, "revoked", expiration).Err() // key, value, expiration
}

func (r *RedisTokenRepository) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	val, err := r.client.Get(ctx, jti).Result()
	if err == redis.Nil { // key not found == not blacklisted
		return false, nil
	} else if err != nil {
		return false, err
	}
	// If the key exists, the token is revoked
	return val == "revoked", nil
}
