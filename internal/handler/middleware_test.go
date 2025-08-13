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
