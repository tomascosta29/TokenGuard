package repository

import (
	"context"
	"sync"
	"time"
)

// InMemoryTokenRepository is an in-memory implementation of TokenRepository.
// It's suitable for development, testing, and single-instance deployments.
type InMemoryTokenRepository struct {
	blacklist map[string]time.Time // Stores JTI -> Expiration Time
	mu        sync.RWMutex         // Protects concurrent access to the map
}

// NewInMemoryTokenRepository creates a new InMemoryTokenRepository.
func NewInMemoryTokenRepository() *InMemoryTokenRepository {
	return &InMemoryTokenRepository{
		blacklist: make(map[string]time.Time),
	}
}

// RevokeToken adds a token's JTI to the blacklist with an expiration time.
func (r *InMemoryTokenRepository) RevokeToken(ctx context.Context, jti string, expiration time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Convert duration to expiration time
	expireAt := time.Now().Add(expiration)

	r.blacklist[jti] = expireAt

	// go routine to clean up
	go r.cleanup(jti, expiration)
	return nil
}

// IsTokenRevoked checks if a token's JTI is present in the blacklist.
func (r *InMemoryTokenRepository) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	expireAt, ok := r.blacklist[jti]
	if !ok {
		return false, nil // Not found, so not revoked
	}

	// Check if the token has expired
	if time.Now().After(expireAt) {
		// it is expired, so remove it
		return false, nil
	}

	return true, nil // Found, and not expired, so it's revoked
}

// cleanup removes the JTI from the map when it is expired
func (r *InMemoryTokenRepository) cleanup(jti string, expiration time.Duration) {
	time.Sleep(expiration)

	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.blacklist, jti)
}
