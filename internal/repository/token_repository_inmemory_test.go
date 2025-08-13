package repository

import (
	"testing"
)

func TestInMemoryTokenRepository(t *testing.T) {
	repo := NewInMemoryTokenRepository()
	cleanup := func() {
		// No cleanup needed for the in-memory repository, but we must provide a function.
	}
	RunTokenRepositoryTests(t, repo, cleanup)
}
