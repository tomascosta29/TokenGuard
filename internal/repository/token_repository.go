// File: TokenGuard/./internal/repository/token_repository.go
package repository

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
)

type TokenRepository interface {
	RevokeToken(ctx context.Context, userID uuid.UUID, jti string, expiration time.Duration) error
	IsTokenRevoked(ctx context.Context, jti string) (bool, error)
	CreateRefreshToken(ctx context.Context, userID uuid.UUID, token string, expiration time.Duration) error // New Function
	GetRefreshToken(ctx context.Context, token string) (uuid.UUID, error)                                   // New Function
	RevokeRefreshToken(ctx context.Context, token string) error                                             // New Function
	RevokeUserTokens(ctx context.Context, userID uuid.UUID) error
}

type RedisClient interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Get(ctx context.Context, key string) *redis.StringCmd
	Ping(ctx context.Context) *redis.StatusCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	Close() error
	SAdd(ctx context.Context, key string, members ...interface{}) *redis.IntCmd
	SMembers(ctx context.Context, key string) *redis.StringSliceCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
	TxPipeline() redis.Pipeliner
}
