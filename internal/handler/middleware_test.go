package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthMiddleware_InvalidPrefixAndMissingHeader(t *testing.T) {
	t.Run("missing header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		mw := AuthMiddleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		mw.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Equal(t, "Authorization header required\n", rr.Body.String())
	})

	t.Run("invalid prefix", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Token abc")
		rr := httptest.NewRecorder()
		mw := AuthMiddleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		mw.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Equal(t, "invalid authorization header\n", rr.Body.String())
	})
}
