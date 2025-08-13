package handler

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAuthMiddleware(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockTokenService := new(MockTokenService) // from auth_handler_test.go

	// The handler that should be protected
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Create the middleware instance
	middleware := AuthMiddleware(mockTokenService, logger)
	handlerToTest := middleware(protectedHandler)

	t.Run("missing header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		recorder := httptest.NewRecorder()

		handlerToTest.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusUnauthorized, recorder.Code)
		assertErrorResponse(t, recorder.Body, "Authorization header required")
	})

	t.Run("invalid prefix", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Token abc")
		recorder := httptest.NewRecorder()

		handlerToTest.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusUnauthorized, recorder.Code)
		assertErrorResponse(t, recorder.Body, "invalid authorization header")
	})

	t.Run("invalid token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer invalid")
		recorder := httptest.NewRecorder()

		mockTokenService.On("ValidateToken", mock.Anything, "invalid").Return(nil, assert.AnError).Once()

		handlerToTest.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusUnauthorized, recorder.Code)
		assertErrorResponse(t, recorder.Body, "Invalid token")
		mockTokenService.AssertExpectations(t)
	})

	t.Run("valid token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer valid")
		recorder := httptest.NewRecorder()

		mockTokenService.On("ValidateToken", mock.Anything, "valid").Return(nil, nil).Once()

		handlerToTest.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "OK", recorder.Body.String())
		mockTokenService.AssertExpectations(t)
	})
}

func TestRateLimitMiddleware(t *testing.T) {
	// Create a rate limiter that allows 1 request per second with a burst of 1.
	limiter := NewIPRateLimiter(1, 1)

	// The handler that should be protected
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Create the middleware instance
	middleware := RateLimitMiddleware(limiter)
	handlerToTest := middleware(protectedHandler)

	t.Run("allows request within limit", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.0.2.1:1234" // Mock client IP
		recorder := httptest.NewRecorder()

		handlerToTest.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "OK", recorder.Body.String())
	})

	t.Run("blocks request exceeding limit", func(t *testing.T) {
		// First request should be allowed
		req1 := httptest.NewRequest("GET", "/", nil)
		req1.RemoteAddr = "192.0.2.2:1234" // New mock client IP
		recorder1 := httptest.NewRecorder()
		handlerToTest.ServeHTTP(recorder1, req1)
		assert.Equal(t, http.StatusOK, recorder1.Code)

		// Second request from the same IP should be blocked
		req2 := httptest.NewRequest("GET", "/", nil)
		req2.RemoteAddr = "192.0.2.2:1234"
		recorder2 := httptest.NewRecorder()
		handlerToTest.ServeHTTP(recorder2, req2)

		assert.Equal(t, http.StatusTooManyRequests, recorder2.Code)
		assertErrorResponse(t, recorder2.Body, "Too Many Requests")
	})
}
