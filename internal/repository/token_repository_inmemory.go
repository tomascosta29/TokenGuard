package repository

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
)

type blacklistItem struct {
	UserID     uuid.UUID
	Expiration time.Time
}

// InMemoryTokenRepository is an in-memory implementation of TokenRepository.
type InMemoryTokenRepository struct {
	blacklist     map[string]blacklistItem
	mu            sync.RWMutex
	refreshTokens map[string]uuid.UUID
}

// NewInMemoryTokenRepository creates a new InMemoryTokenRepository.
func NewInMemoryTokenRepository() *InMemoryTokenRepository {
	log.Println("NewInMemoryTokenRepository: Creating new in-memory token repository")
	return &InMemoryTokenRepository{
		blacklist:     make(map[string]blacklistItem),
		refreshTokens: make(map[string]uuid.UUID),
	}
}

// RevokeToken adds a token's JTI to the blacklist with an expiration time and user ID.
func (r *InMemoryTokenRepository) RevokeToken(ctx context.Context, userID uuid.UUID, jti string, expiration time.Duration) error {
	log.Printf("RevokeToken: Revoking token with JTI %s for user %s", jti, userID)
	r.mu.Lock()
	defer r.mu.Unlock()

	expireAt := time.Now().Add(expiration)
	r.blacklist[jti] = blacklistItem{
		UserID:     userID,
		Expiration: expireAt,
	}

	return nil
}

// IsTokenRevoked checks if a token's JTI is present in the blacklist.
func (r *InMemoryTokenRepository) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	log.Printf("IsTokenRevoked: Checking if token with JTI %s is revoked", jti)
	r.mu.RLock()
	defer r.mu.RUnlock()

	item, ok := r.blacklist[jti]
	if !ok {
		log.Printf("IsTokenRevoked: Token with JTI %s is not revoked", jti)
		return false, nil
	}

	if time.Now().After(item.Expiration) {
		log.Printf("IsTokenRevoked: Token with JTI %s is expired, removing from blacklist", jti)
		r.mu.RUnlock() // Release read lock to acquire write lock
		r.mu.Lock()
		delete(r.blacklist, jti)
		r.mu.Unlock()
		r.mu.RLock() // Re-acquire read lock
		return false, nil
	}

	log.Printf("IsTokenRevoked: Token with JTI %s is revoked", jti)
	return true, nil
}

// RevokeUserTokens removes all tokens for a given user ID from the blacklist.
func (r *InMemoryTokenRepository) RevokeUserTokens(ctx context.Context, userID uuid.UUID) error {
	log.Printf("RevokeUserTokens: Revoking all tokens for user %s", userID)
	r.mu.Lock()
	defer r.mu.Unlock()

	for jti, item := range r.blacklist {
		if item.UserID == userID {
			delete(r.blacklist, jti)
		}
	}

	// Also revoke refresh tokens
	for token, id := range r.refreshTokens {
		if id == userID {
			delete(r.refreshTokens, token)
		}
	}

	log.Printf("RevokeUserTokens: All tokens for user %s have been revoked", userID)
	return nil
}

// CreateRefreshToken stores the refresh token in memory, associated with the user ID.
func (r *InMemoryTokenRepository) CreateRefreshToken(ctx context.Context, userID uuid.UUID, token string, expiration time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.refreshTokens[token] = userID
	log.Printf("CreateRefreshToken: Refresh token stored successfully for user %s", userID)
	return nil
}

// GetRefreshToken retrieves the user ID associated with the refresh token from memory.
func (r *InMemoryTokenRepository) GetRefreshToken(ctx context.Context, token string) (uuid.UUID, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	userID, ok := r.refreshTokens[token]
	if !ok {
		log.Println("GetRefreshToken: Refresh token not found")
		return uuid.Nil, fmt.Errorf("refresh token not found")
	}

	log.Printf("GetRefreshToken: User ID %s retrieved successfully for refresh token", userID)
	return userID, nil
}

// RevokeRefreshToken removes the refresh token from memory.
func (r *InMemoryTokenRepository) RevokeRefreshToken(ctx context.Context, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.refreshTokens, token)
	log.Printf("RevokeRefreshToken: Refresh token revoked successfully")
	return nil
}
