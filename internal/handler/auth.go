package handler

import (
	"fmt"
	"strings"
)

// extractBearerToken validates an Authorization header and returns the bearer token.
// It ensures the header has the expected "Bearer " prefix and strips it.
func extractBearerToken(authHeader string) (string, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", fmt.Errorf("invalid authorization header")
	}
	return strings.TrimPrefix(authHeader, prefix), nil
}
