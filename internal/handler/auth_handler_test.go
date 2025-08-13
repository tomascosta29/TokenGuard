package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/tomascosta29/TokenGuard/internal/model"
)

// MockUserService is a mock for the UserService.
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) RegisterUser(ctx context.Context, req *model.RegisterRequest) (*model.User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserService) LoginUser(ctx context.Context, req *model.LoginRequest) (*model.User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserService) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *MockUserService) CheckPasswordHash(password, hash string) bool {
	args := m.Called(password, hash)
	return args.Bool(0)
}

// MockTokenService is a mock for the TokenService.
type MockTokenService struct {
	mock.Mock
}

func (m *MockTokenService) GenerateToken(ctx context.Context, userID uuid.UUID) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

func (m *MockTokenService) ValidateToken(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	args := m.Called(ctx, tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(jwt.MapClaims), args.Error(1)
}

func (m *MockTokenService) RevokeToken(ctx context.Context, tokenString string) error {
	args := m.Called(ctx, tokenString)
	return args.Error(0)
}

func (m *MockTokenService) GenerateRefreshToken(ctx context.Context, userID uuid.UUID) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

func (m *MockTokenService) ValidateRefreshToken(ctx context.Context, refreshToken string) (uuid.UUID, error) {
	args := m.Called(ctx, refreshToken)
	if id, ok := args.Get(0).(uuid.UUID); ok {
		return id, args.Error(1)
	}
	return uuid.Nil, args.Error(1)
}

func (m *MockTokenService) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	args := m.Called(ctx, refreshToken)
	return args.Error(0)
}

func (m *MockTokenService) RevokeUserTokens(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// setupTest creates a new AuthHandler with mock services and a discard logger.
func setupTest(t *testing.T) (*AuthHandler, *MockUserService, *MockTokenService) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockUserService := new(MockUserService)
	mockTokenService := new(MockTokenService)
	handler := NewAuthHandler(mockUserService, mockTokenService, logger, "test-admin-key")
	return handler, mockUserService, mockTokenService
}

func TestAuthHandler_AdminAuthMiddleware(t *testing.T) {
	handler, _, _ := setupTest(t)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	middleware := handler.AdminAuthMiddleware(dummyHandler)

	t.Run("Valid API Key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer test-admin-key")
		recorder := httptest.NewRecorder()
		middleware.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusOK, recorder.Code)
	})

	t.Run("Invalid API Key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer wrong-key")
		recorder := httptest.NewRecorder()
		middleware.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusUnauthorized, recorder.Code)
		assertErrorResponse(t, recorder.Body, "Invalid admin API key")
	})

	t.Run("Missing API Key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		recorder := httptest.NewRecorder()
		middleware.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusUnauthorized, recorder.Code)
		assertErrorResponse(t, recorder.Body, "Authorization header required")
	})
}

// assertErrorResponse checks for a JSON error response.
func assertErrorResponse(t *testing.T, body *bytes.Buffer, expectedMsg string) {
	t.Helper()
	var errResp map[string]string
	err := json.Unmarshal(body.Bytes(), &errResp)
	assert.NoError(t, err, "Failed to unmarshal error response")
	assert.Equal(t, expectedMsg, errResp["error"])
}

func TestAuthHandler_RegisterHandler(t *testing.T) {
	t.Run("Successful registration", func(t *testing.T) {
		handler, mockUserService, _ := setupTest(t)
		reqBody := `{"username": "testuser", "email": "test@example.com", "password": "Password123!"}`
		req := httptest.NewRequest("POST", "/v1/auth/register", bytes.NewBufferString(reqBody))
		recorder := httptest.NewRecorder()

		mockUserService.On("RegisterUser", mock.Anything, mock.AnythingOfType("*model.RegisterRequest")).Return(&model.User{}, nil).Once()

		handler.RegisterHandler(recorder, req)

		assert.Equal(t, http.StatusCreated, recorder.Code)
		var resp map[string]string
		json.Unmarshal(recorder.Body.Bytes(), &resp)
		assert.Equal(t, "User registered successfully", resp["message"])
		mockUserService.AssertExpectations(t)
	})

	t.Run("Invalid request body", func(t *testing.T) {
		handler, _, _ := setupTest(t)
		req := httptest.NewRequest("POST", "/v1/auth/register", bytes.NewBufferString("invalid json"))
		recorder := httptest.NewRecorder()

		handler.RegisterHandler(recorder, req)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)
		assertErrorResponse(t, recorder.Body, "Invalid request body")
	})

	t.Run("Invalid username format", func(t *testing.T) {
		handler, _, _ := setupTest(t)
		reqBody := `{"username": "a", "email": "test@example.com", "password": "Password123!"}`
		req := httptest.NewRequest("POST", "/v1/auth/register", bytes.NewBufferString(reqBody))
		recorder := httptest.NewRecorder()

		handler.RegisterHandler(recorder, req)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)
		assertErrorResponse(t, recorder.Body, "username must be 3-20 characters long and contain only letters and numbers")
	})

	t.Run("Registration error", func(t *testing.T) {
		handler, mockUserService, _ := setupTest(t)
		reqBody := `{"username": "testuser", "email": "test@example.com", "password": "Password123!"}`
		req := httptest.NewRequest("POST", "/v1/auth/register", bytes.NewBufferString(reqBody))
		recorder := httptest.NewRecorder()

		mockUserService.On("RegisterUser", mock.Anything, mock.AnythingOfType("*model.RegisterRequest")).Return(nil, errors.New("username already exists")).Once()

		handler.RegisterHandler(recorder, req)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)
		assertErrorResponse(t, recorder.Body, "Registration failed")
		mockUserService.AssertExpectations(t)
	})
}

func TestAuthHandler_LoginHandler(t *testing.T) {
	t.Run("Successful login", func(t *testing.T) {
		handler, mockUserService, mockTokenService := setupTest(t)
		reqBody := `{"username": "testuser", "password": "password123"}`
		req := httptest.NewRequest("POST", "/v1/auth/login", bytes.NewBufferString(reqBody))
		recorder := httptest.NewRecorder()
		userID := uuid.New()

		mockUserService.On("LoginUser", mock.Anything, mock.AnythingOfType("*model.LoginRequest")).Return(&model.User{ID: userID}, nil).Once()
		mockTokenService.On("GenerateToken", mock.Anything, userID).Return("testtoken", nil).Once()
		mockTokenService.On("GenerateRefreshToken", mock.Anything, userID).Return("testrefreshtoken", nil).Once()

		handler.LoginHandler(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
		var response map[string]string
		json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.Equal(t, "testtoken", response["token"])
		assert.Equal(t, "testrefreshtoken", response["refresh_token"])
		mockUserService.AssertExpectations(t)
		mockTokenService.AssertExpectations(t)
	})

	t.Run("Invalid login credentials", func(t *testing.T) {
		handler, mockUserService, _ := setupTest(t)
		reqBody := `{"username": "testuser", "password": "wrongpassword"}`
		req := httptest.NewRequest("POST", "/v1/auth/login", bytes.NewBufferString(reqBody))
		recorder := httptest.NewRecorder()

		mockUserService.On("LoginUser", mock.Anything, mock.AnythingOfType("*model.LoginRequest")).Return(nil, errors.New("invalid credentials")).Once()

		handler.LoginHandler(recorder, req)

		assert.Equal(t, http.StatusUnauthorized, recorder.Code)
		assertErrorResponse(t, recorder.Body, "Invalid username or password")
		mockUserService.AssertExpectations(t)
	})
}

func TestAuthHandler_ValidateTokenHandler(t *testing.T) {
	t.Run("Successful validation", func(t *testing.T) {
		handler, _, mockTokenService := setupTest(t)
		tokenString := "valid-token"
		req := httptest.NewRequest("GET", "/v1/auth/validate", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		recorder := httptest.NewRecorder()

		mockTokenService.On("ValidateToken", mock.Anything, tokenString).Return(jwt.MapClaims{"sub": "testuser"}, nil).Once()

		handler.ValidateTokenHandler(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
		var response map[string]interface{}
		json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.Equal(t, "testuser", response["sub"])
		mockTokenService.AssertExpectations(t)
	})

	t.Run("Missing header", func(t *testing.T) {
		handler, _, _ := setupTest(t)
		req := httptest.NewRequest("GET", "/v1/auth/validate", nil)
		recorder := httptest.NewRecorder()

		handler.ValidateTokenHandler(recorder, req)

		assert.Equal(t, http.StatusUnauthorized, recorder.Code)
		assertErrorResponse(t, recorder.Body, "Authorization header required")
	})

	t.Run("Invalid token", func(t *testing.T) {
		handler, _, mockTokenService := setupTest(t)
		req := httptest.NewRequest("GET", "/v1/auth/validate", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		recorder := httptest.NewRecorder()

		mockTokenService.On("ValidateToken", mock.Anything, "invalid-token").Return(nil, errors.New("token is invalid")).Once()

		handler.ValidateTokenHandler(recorder, req)

		assert.Equal(t, http.StatusUnauthorized, recorder.Code)
		assertErrorResponse(t, recorder.Body, "Invalid token")
		mockTokenService.AssertExpectations(t)
	})
}

func TestAuthHandler_LogoutHandler(t *testing.T) {
	t.Run("Successful logout", func(t *testing.T) {
		handler, _, mockTokenService := setupTest(t)
		tokenString := "valid-token"
		req := httptest.NewRequest("POST", "/v1/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		recorder := httptest.NewRecorder()

		mockTokenService.On("RevokeToken", mock.Anything, tokenString).Return(nil).Once()

		handler.LogoutHandler(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
		var resp map[string]string
		json.Unmarshal(recorder.Body.Bytes(), &resp)
		assert.Equal(t, "User logged out successfully", resp["message"])
		mockTokenService.AssertExpectations(t)
	})

	t.Run("Revoke token error", func(t *testing.T) {
		handler, _, mockTokenService := setupTest(t)
		tokenString := "valid-token"
		req := httptest.NewRequest("POST", "/v1/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		recorder := httptest.NewRecorder()

		mockTokenService.On("RevokeToken", mock.Anything, tokenString).Return(errors.New("db error")).Once()

		handler.LogoutHandler(recorder, req)

		assert.Equal(t, http.StatusUnauthorized, recorder.Code)
		assertErrorResponse(t, recorder.Body, "Could not log out")
		mockTokenService.AssertExpectations(t)
	})
}

func TestAuthHandler_RefreshHandler(t *testing.T) {
	t.Run("Successful refresh", func(t *testing.T) {
		handler, _, mockTokenService := setupTest(t)
		refreshToken := "valid-refresh-token"
		userID := uuid.New()
		reqBody := `{"refresh_token": "` + refreshToken + `"}`
		req := httptest.NewRequest("POST", "/v1/auth/refresh", bytes.NewBufferString(reqBody))
		recorder := httptest.NewRecorder()

		mockTokenService.On("ValidateRefreshToken", mock.Anything, refreshToken).Return(userID, nil).Once()
		mockTokenService.On("RevokeRefreshToken", mock.Anything, refreshToken).Return(nil).Once()
		mockTokenService.On("GenerateToken", mock.Anything, userID).Return("new-access-token", nil).Once()
		mockTokenService.On("GenerateRefreshToken", mock.Anything, userID).Return("new-refresh-token", nil).Once()

		handler.RefreshHandler(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
		var resp map[string]string
		json.Unmarshal(recorder.Body.Bytes(), &resp)
		assert.Equal(t, "new-access-token", resp["access_token"])
		assert.Equal(t, "new-refresh-token", resp["refresh_token"])
		mockTokenService.AssertExpectations(t)
	})

	t.Run("Invalid refresh token", func(t *testing.T) {
		handler, _, mockTokenService := setupTest(t)
		reqBody := `{"refresh_token": "invalid-token"}`
		req := httptest.NewRequest("POST", "/v1/auth/refresh", bytes.NewBufferString(reqBody))
		recorder := httptest.NewRecorder()

		mockTokenService.On("ValidateRefreshToken", mock.Anything, "invalid-token").Return(uuid.Nil, errors.New("invalid token")).Once()

		handler.RefreshHandler(recorder, req)

		assert.Equal(t, http.StatusUnauthorized, recorder.Code)
		assertErrorResponse(t, recorder.Body, "Invalid refresh token")
		mockTokenService.AssertExpectations(t)
	})
}

func TestValidatePasswordComplexity(t *testing.T) {
	testCases := []struct {
		name     string
		password string
		errMsg   string
	}{
		{name: "Valid password", password: "Password123!", errMsg: ""},
		{name: "Too short", password: "Short1!", errMsg: "password must be between 8 and 128 characters long"},
		{name: "Too long", password: strings.Repeat("a", 129) + "B!1", errMsg: "password must be between 8 and 128 characters long"},
		{name: "No uppercase", password: "nouppercase123!", errMsg: "password must contain at least one uppercase letter"},
		{name: "No lowercase", password: "NOLOWERCASE123!", errMsg: "password must contain at least one lowercase letter"},
		{name: "No number", password: "NoNumber!@", errMsg: "password must contain at least one number"},
		{name: "No special char", password: "NoSpecial123", errMsg: "password must contain at least one special character"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePasswordComplexity(tc.password)
			if tc.errMsg == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.errMsg)
			}
		})
	}
}

func TestAuthHandler_AdminRevokeHandler(t *testing.T) {
	t.Run("Successful revoke", func(t *testing.T) {
		handler, _, mockTokenService := setupTest(t)
		userID := uuid.New()
		reqBody := `{"user_id": "` + userID.String() + `"}`
		req := httptest.NewRequest("POST", "/v1/admin/auth/revoke", bytes.NewBufferString(reqBody))
		recorder := httptest.NewRecorder()

		mockTokenService.On("RevokeUserTokens", mock.Anything, userID).Return(nil).Once()

		handler.AdminRevokeHandler(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
		var resp map[string]string
		json.Unmarshal(recorder.Body.Bytes(), &resp)
		assert.Equal(t, "User tokens revoked successfully", resp["message"])
		mockTokenService.AssertExpectations(t)
	})

	t.Run("Invalid user ID", func(t *testing.T) {
		handler, _, _ := setupTest(t)
		reqBody := `{"user_id": "invalid-uuid"}`
		req := httptest.NewRequest("POST", "/v1/admin/auth/revoke", bytes.NewBufferString(reqBody))
		recorder := httptest.NewRecorder()

		handler.AdminRevokeHandler(recorder, req)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)
		assertErrorResponse(t, recorder.Body, "Invalid user ID format")
	})
}

func TestValidateUsername(t *testing.T) {
	testCases := []struct {
		name     string
		username string
		errMsg   string
	}{
		{name: "Valid username", username: "validUser", errMsg: ""},
		{name: "Too short", username: "ab", errMsg: "username must be 3-20 characters long and contain only letters and numbers"},
		{name: "Invalid character", username: "invalid!", errMsg: "username must be 3-20 characters long and contain only letters and numbers"},
		{name: "Too long", username: "thisusernameiswaytoolongandshouldfail", errMsg: "username must be 3-20 characters long and contain only letters and numbers"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUsername(tc.username)
			if tc.errMsg == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.errMsg)
			}
		})
	}
}
