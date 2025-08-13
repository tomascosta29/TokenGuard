package repository

import (
	"context"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
)

// MockRedisClient is a mock of the RedisClient interface.
type MockRedisClient struct {
	data map[string]string
	sets map[string][]string
	exp  map[string]time.Time
}

func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{
		data: make(map[string]string),
		sets: make(map[string][]string),
		exp:  make(map[string]time.Time),
	}
}

func (m *MockRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	m.data[key] = value.(string)
	if expiration > 0 {
		m.exp[key] = time.Now().Add(expiration)
	}
	return redis.NewStatusResult("", nil)
}

func (m *MockRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	if exp, ok := m.exp[key]; ok && time.Now().After(exp) {
		delete(m.data, key)
		delete(m.exp, key)
	}
	val, ok := m.data[key]
	if !ok {
		return redis.NewStringResult("", redis.Nil)
	}
	return redis.NewStringResult(val, nil)
}

func (m *MockRedisClient) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	count := 0
	for _, key := range keys {
		if _, ok := m.data[key]; ok {
			delete(m.data, key)
			delete(m.exp, key)
			count++
		}
		if _, ok := m.sets[key]; ok {
			delete(m.sets, key)
			count++
		}
	}
	return redis.NewIntCmd(ctx, int64(count))
}

func (m *MockRedisClient) Ping(ctx context.Context) *redis.StatusCmd {
	return redis.NewStatusResult("PONG", nil)
}

func (m *MockRedisClient) Close() error {
	return nil
}

func (m *MockRedisClient) SAdd(ctx context.Context, key string, members ...interface{}) *redis.IntCmd {
	for _, member := range members {
		m.sets[key] = append(m.sets[key], member.(string))
	}
	return redis.NewIntCmd(ctx, int64(len(members)))
}

func (m *MockRedisClient) SMembers(ctx context.Context, key string) *redis.StringSliceCmd {
	return redis.NewStringSliceResult(m.sets[key], nil)
}

func (m *MockRedisClient) Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd {
	m.exp[key] = time.Now().Add(expiration)
	return redis.NewBoolResult(true, nil)
}

func (m *MockRedisClient) TxPipeline() redis.Pipeliner {
	return &MockPipeliner{mock: m}
}

type MockPipeliner struct {
	mock *MockRedisClient
	redis.Pipeliner
}

func (p *MockPipeliner) Exec(ctx context.Context) ([]redis.Cmder, error) {
	return nil, nil
}

func (p *MockPipeliner) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	return p.mock.Set(ctx, key, value, expiration)
}

func (p *MockPipeliner) SAdd(ctx context.Context, key string, members ...interface{}) *redis.IntCmd {
	return p.mock.SAdd(ctx, key, members...)
}

func (p *MockPipeliner) Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd {
	return p.mock.Expire(ctx, key, expiration)
}

func (p *MockPipeliner) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	return p.mock.Del(ctx, keys...)
}

func TestRedisTokenRepositoryWithMock(t *testing.T) {
	mockClient := NewMockRedisClient()
	repo := &RedisTokenRepository{client: mockClient}
	cleanup := func() {} // No cleanup needed for mock

	RunTokenRepositoryTests(t, repo, cleanup)
}
