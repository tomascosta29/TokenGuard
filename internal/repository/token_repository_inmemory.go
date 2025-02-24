// File: /home/fcosta/CostaAuth/./internal/repository/token_repository_inmemory.go
package repository

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
)

// InMemoryTokenRepository is an in-memory implementation of TokenRepository.
// It's suitable for development, testing, and single-instance deployments.
type InMemoryTokenRepository struct {
	blacklist     map[string]time.Time // Stores JTI -> Expiration Time
	mu            sync.RWMutex         // Protects concurrent access to the map
	refreshTokens map[string]uuid.UUID // Stores RefreshToken -> UserID
}

// NewInMemoryTokenRepository creates a new InMemoryTokenRepository.
func NewInMemoryTokenRepository() *InMemoryTokenRepository {
	log.Println("NewInMemoryTokenRepository: Creating new in-memory token repository")
	return &InMemoryTokenRepository{
		blacklist:     make(map[string]time.Time),
		refreshTokens: make(map[string]uuid.UUID),
	}
}

// RevokeToken adds a token's JTI to the blacklist with an expiration time.
func (r *InMemoryTokenRepository) RevokeToken(ctx context.Context, jti string, expiration time.Duration) error {
	log.Printf("RevokeToken: Revoking token with JTI %s", jti)
	r.mu.Lock()
	defer r.mu.Unlock()

	// Convert duration to expiration time
	expireAt := time.Now().Add(expiration)

	r.blacklist[jti] = expireAt

	// go routine to clean up
	go r.cleanup(jti, expiration)
	log.Printf("RevokeToken: Token with JTI %s revoked successfully", jti)
	return nil
}

// IsTokenRevoked checks if a token's JTI is present in the blacklist.
func (r *InMemoryTokenRepository) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	log.Printf("IsTokenRevoked: Checking if token with JTI %s is revoked", jti)
	r.mu.RLock()
	defer r.mu.RUnlock()

	expireAt, ok := r.blacklist[jti]
	if !ok {
		log.Printf("IsTokenRevoked: Token with JTI %s is not revoked", jti)
		return false, nil // Not found, so not revoked
	}

	// Check if the token has expired
	if time.Now().After(expireAt) {
		// it is expired, so remove it
		log.Printf("IsTokenRevoked: Token with JTI %s is expired, removing from blacklist", jti)
		return false, nil
	}

	log.Printf("IsTokenRevoked: Token with JTI %s is revoked", jti)
	return true, nil // Found, and not expired, so it's revoked
}

// cleanup removes the JTI from the map when it is expired
func (r *InMemoryTokenRepository) cleanup(jti string, expiration time.Duration) {
	time.Sleep(expiration)

	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.blacklist, jti)
	log.Printf("cleanup: Token with JTI %s has expired and been removed from blacklist", jti)
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
