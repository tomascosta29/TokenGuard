// File: /home/fcosta/CostaAuth/./internal/repository/token_repository.go
package repository

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
)

type TokenRepository interface {
	RevokeToken(ctx context.Context, jti string, expiration time.Duration) error
	IsTokenRevoked(ctx context.Context, jti string) (bool, error)
}

type RedisClient interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Get(ctx context.Context, key string) *redis.StringCmd
	Ping(ctx context.Context) *redis.StatusCmd
}
