package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/tomascosta29/CostaAuth/internal/model"
)

type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) RegisterUser(ctx context.Context, req *model.RegisterRequest) (*model.User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil { // handle nil case
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserService) LoginUser(ctx context.Context, req *model.LoginRequest) (*model.User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil { // handle nil case
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserService) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

// CheckPasswordHash compares a password with its hash
func (m *MockUserService) CheckPasswordHash(password, hash string) bool {
	args := m.Called(password, hash)
	return args.Bool(0)
}

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
	return args.Get(0).(jwt.MapClaims), args.Error(1) // cast to map
}

func (m *MockTokenService) RevokeToken(ctx context.Context, tokenString string) error {
	args := m.Called(ctx, tokenString)
	return args.Error(0)
}

func TestAuthHandler_RegisterHandler(t *testing.T) {
	mockUserService := new(MockUserService)
	mockTokenService := new(MockTokenService)
	handler := NewAuthHandler(mockUserService, mockTokenService)

	// Test case: Successful registration
	reqBody := `{"username": "testuser", "email": "test@example.com", "password": "password123"}`
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBufferString(reqBody))
	recorder := httptest.NewRecorder()
	// Mock behavior for successful registration
	mockUserService.On("RegisterUser", mock.Anything, mock.AnythingOfType("*model.RegisterRequest")).Return(&model.User{}, nil)

	handler.RegisterHandler(recorder, req)

	assert.Equal(t, http.StatusCreated, recorder.Code)
	assert.Equal(t, "User registered successfully\n", recorder.Body.String())

	// Reset the mock for the next test case!  This is important.
	mockUserService = new(MockUserService)
	mockTokenService = new(MockTokenService)
	handler = NewAuthHandler(mockUserService, mockTokenService)

	// Test case: Invalid request body
	req, _ = http.NewRequest("POST", "/auth/register", bytes.NewBufferString("invalid json"))
	recorder = httptest.NewRecorder()

	handler.RegisterHandler(recorder, req)
	assert.Equal(t, http.StatusBadRequest, recorder.Code)

	// Reset the mock for the next test case
	mockUserService = new(MockUserService)
	mockTokenService = new(MockTokenService)
	handler = NewAuthHandler(mockUserService, mockTokenService)

	// Test case: Registration error (e.g., username already exists)
	req, _ = http.NewRequest("POST", "/auth/register", bytes.NewBufferString(reqBody)) // valid request
	recorder = httptest.NewRecorder()

	// Mock behavior for registration error
	mockUserService.On("RegisterUser", mock.Anything, mock.AnythingOfType("*model.RegisterRequest")).Return(nil, errors.New("some error"))

	handler.RegisterHandler(recorder, req)
	assert.Equal(t, http.StatusBadRequest, recorder.Code) // expect 400

	// The mock expectations must be asserted *AFTER* the handler call that uses the mock.
	mockUserService.AssertExpectations(t)
	mockTokenService.AssertExpectations(t)
}

func TestAuthHandler_LoginHandler(t *testing.T) {
	mockUserService := new(MockUserService)
	mockTokenService := new(MockTokenService)
	handler := NewAuthHandler(mockUserService, mockTokenService)

	// Test case: Successful login
	reqBody := `{"username": "testuser", "password": "password123"}`
	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBufferString(reqBody))
	recorder := httptest.NewRecorder()
	mockUserService.On("LoginUser", mock.Anything, mock.AnythingOfType("*model.LoginRequest")).Return(&model.User{ID: uuid.New()}, nil)
	mockTokenService.On("GenerateToken", mock.Anything, mock.AnythingOfType("uuid.UUID")).Return("testtoken", nil)

	handler.LoginHandler(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	var response map[string]string
	json.Unmarshal(recorder.Body.Bytes(), &response)
	assert.Equal(t, "testtoken", response["token"])

	// Reset mocks
	mockUserService = new(MockUserService)
	mockTokenService = new(MockTokenService)
	handler = NewAuthHandler(mockUserService, mockTokenService)

	// Test case: Invalid request body
	req, _ = http.NewRequest("POST", "/auth/login", bytes.NewBufferString("invalid json"))
	recorder = httptest.NewRecorder()

	handler.LoginHandler(recorder, req)
	assert.Equal(t, http.StatusBadRequest, recorder.Code)

	// Reset mocks
	mockUserService = new(MockUserService)
	mockTokenService = new(MockTokenService)
	handler = NewAuthHandler(mockUserService, mockTokenService)

	// Test case: Login error (e.g., user not found)
	req, _ = http.NewRequest("POST", "/auth/login", bytes.NewBufferString(reqBody)) // valid request
	recorder = httptest.NewRecorder()

	mockUserService.On("LoginUser", mock.Anything, mock.AnythingOfType("*model.LoginRequest")).Return(nil, errors.New("some error"))

	handler.LoginHandler(recorder, req)
	assert.Equal(t, http.StatusUnauthorized, recorder.Code) // expect 401

	// Assert expectations *after* the handler call and assertions.
	mockUserService.AssertExpectations(t)
	mockTokenService.AssertExpectations(t)
}

func TestAuthHandler_ValidateTokenHandler(t *testing.T) {
	mockUserService := new(MockUserService)
	mockTokenService := new(MockTokenService)
	handler := NewAuthHandler(mockUserService, mockTokenService)

	// Test case: Successful validation
	tokenString := "valid-token" // dummy
	req, _ := http.NewRequest("GET", "/auth/validate", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	recorder := httptest.NewRecorder()

	mockTokenService.On("ValidateToken", mock.Anything, tokenString).Return(jwt.MapClaims{"sub": "testuser"}, nil)

	handler.ValidateTokenHandler(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	var response map[string]interface{}

	json.Unmarshal(recorder.Body.Bytes(), &response)
	assert.Equal(t, "testuser", response["sub"])

	// Test case: missing header
	req, _ = http.NewRequest("GET", "/auth/validate", nil)
	recorder = httptest.NewRecorder()
	handler.ValidateTokenHandler(recorder, req)
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

	// Test case: Invalid token
	req, _ = http.NewRequest("GET", "/auth/validate", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	recorder = httptest.NewRecorder()

	mockTokenService.On("ValidateToken", mock.Anything, "invalid-token").Return(nil, assert.AnError)

	handler.ValidateTokenHandler(recorder, req)
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

	mockUserService.AssertExpectations(t)
	mockTokenService.AssertExpectations(t)
}

func TestAuthHandler_LogoutHandler(t *testing.T) {
	mockUserService := new(MockUserService)
	mockTokenService := new(MockTokenService)
	handler := NewAuthHandler(mockUserService, mockTokenService)
	tokenString := "valid-token" // dummy

	// Test case: Successful logout
	req, _ := http.NewRequest("POST", "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	recorder := httptest.NewRecorder()
	mockTokenService.On("RevokeToken", mock.Anything, tokenString).Return(nil)

	handler.LogoutHandler(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)

	// Test case: missing header
	req, _ = http.NewRequest("POST", "/auth/logout", nil)
	recorder = httptest.NewRecorder()
	handler.LogoutHandler(recorder, req)
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

	// Test case: Revoke token error
	req, _ = http.NewRequest("POST", "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	recorder = httptest.NewRecorder()
	mockTokenService.On("RevokeToken", mock.Anything, "invalid-token").Return(assert.AnError)
	handler.LogoutHandler(recorder, req)
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	mockTokenService.AssertExpectations(t)
	mockUserService.AssertExpectations(t)
}
