// File: /home/fcosta/CostaAuth/./internal/service/user_service_test.go
package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/tomascosta29/CostaAuth/internal/model"
)

// Mock UserRepository for testing the service
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) CreateUser(ctx context.Context, user *model.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil { // important for nil returns
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil { // important for nil returns
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepository) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil { // important for nil returns
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

// Mock PasswordChecker
type MockPasswordChecker struct {
	mock.Mock
}

func (m *MockPasswordChecker) CheckPasswordHash(password, hash string) bool {
	args := m.Called(password, hash)
	return args.Bool(0)
}

func TestUserService_RegisterUser(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockChecker := new(MockPasswordChecker)              // Create a mock PasswordChecker
	userService := NewUserService(mockRepo, mockChecker) // Inject the dependency
	ctx := context.Background()

	// Test case: Successful registration
	req := &model.RegisterRequest{
		Username: "newuser",
		Email:    "newuser@example.com",
		Password: "password123",
	}
	// Mock GetUserByUsername to return nil, nil (user not found)
	mockRepo.On("GetUserByUsername", ctx, req.Username).Return((*model.User)(nil), nil)
	mockRepo.On("GetUserByEmail", ctx, req.Email).Return((*model.User)(nil), nil)

	// Mock CreateUser to return nil (no error)
	mockRepo.On("CreateUser", ctx, mock.AnythingOfType("*model.User")).Return(nil)

	user, err := userService.RegisterUser(ctx, req)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, req.Username, user.Username)
	assert.NotEmpty(t, user.PasswordHash) // Check that password was hashed

	// Test case: Username already exists
	mockRepo = new(MockUserRepository) // Reset mock for next scenario
	mockChecker = new(MockPasswordChecker)
	userService = NewUserService(mockRepo, mockChecker)

	existingUser := &model.User{Username: "existinguser"}
	mockRepo.On("GetUserByUsername", ctx, "existinguser").Return(existingUser, nil)

	req = &model.RegisterRequest{
		Username: "existinguser",
		Email:    "existing@example.com",
		Password: "password123",
	}
	_, err = userService.RegisterUser(ctx, req)
	assert.Error(t, err)
	assert.EqualError(t, err, "username already exists") // check for specific error

	// Test case: Email already exists
	mockRepo = new(MockUserRepository) // Reset mock for next scenario
	mockChecker = new(MockPasswordChecker)
	userService = NewUserService(mockRepo, mockChecker)

	existingUser = &model.User{Email: "existing@email.com"}
	mockRepo.On("GetUserByUsername", ctx, "newuser").Return((*model.User)(nil), nil)
	mockRepo.On("GetUserByEmail", ctx, "existing@email.com").Return(existingUser, nil)
	req = &model.RegisterRequest{
		Username: "newuser",
		Email:    "existing@email.com",
		Password: "password123",
	}
	_, err = userService.RegisterUser(ctx, req)
	assert.Error(t, err)
	assert.EqualError(t, err, "email already exists") // check for specific error

	// Test case: CreateUser returns an error
	mockRepo = new(MockUserRepository)
	mockChecker = new(MockPasswordChecker)
	userService = NewUserService(mockRepo, mockChecker)

	mockRepo.On("GetUserByUsername", ctx, "newuser").Return((*model.User)(nil), nil)          // User not found
	mockRepo.On("GetUserByEmail", ctx, "newuser@example.com").Return((*model.User)(nil), nil) // User not found

	mockRepo.On("CreateUser", ctx, mock.AnythingOfType("*model.User")).Return(errors.New("database error"))

	req = &model.RegisterRequest{Username: "newuser", Email: "newuser@example.com", Password: "password123"}
	_, err = userService.RegisterUser(ctx, req)
	assert.Error(t, err) // Check for any error

	mockRepo.AssertExpectations(t) // Ensure all expected calls were made
	mockChecker.AssertExpectations(t)
}

func TestUserService_LoginUser(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockChecker := new(MockPasswordChecker)              // Create a mock PasswordChecker
	userService := NewUserService(mockRepo, mockChecker) // Inject *both* mocks
	ctx := context.Background()

	// --- Test case: Successful login ---
	req := &model.LoginRequest{Username: "testuser", Password: "password123"}
	existingUser := &model.User{
		ID:           uuid.New(),
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "$2a$10$somehashedpassword", // Example bcrypt hash
		IsActive:     true,
	}
	mockRepo.On("GetUserByUsername", ctx, "testuser").Return(existingUser, nil)
	mockChecker.On("CheckPasswordHash", "password123", "$2a$10$somehashedpassword").Return(true) // Mock the checker

	user, err := userService.LoginUser(ctx, req)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, existingUser, user)

	// Reset Mocks
	mockRepo = new(MockUserRepository)
	mockChecker = new(MockPasswordChecker)              // Create a mock PasswordChecker
	userService = NewUserService(mockRepo, mockChecker) // Inject *both* mocks

	// --- Test case: Wrong password ---
	req = &model.LoginRequest{Username: "testuser", Password: "wrongpassword"}
	mockRepo.On("GetUserByUsername", ctx, "testuser").Return(existingUser, nil)
	mockChecker.On("CheckPasswordHash", "wrongpassword", "$2a$10$somehashedpassword").Return(false) // Mock to fail

	user, err = userService.LoginUser(ctx, req)
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.EqualError(t, err, "invalid credentials")

	// --- Test case: User not found ---
	mockRepo = new(MockUserRepository)
	mockChecker = new(MockPasswordChecker)              // Create a mock PasswordChecker
	userService = NewUserService(mockRepo, mockChecker) // Inject *both* mocks
	mockRepo.On("GetUserByUsername", ctx, "nonexistentuser").Return((*model.User)(nil), nil)

	req = &model.LoginRequest{Username: "nonexistentuser", Password: "password123"}
	_, err = userService.LoginUser(ctx, req)
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.EqualError(t, err, "invalid credentials")

	// --- Test case: GetUserByUsername returns an error ---
	mockRepo = new(MockUserRepository)
	mockChecker = new(MockPasswordChecker)              // Create a mock PasswordChecker
	userService = NewUserService(mockRepo, mockChecker) // Inject *both* mocks

	mockRepo.On("GetUserByUsername", ctx, "erroruser").Return((*model.User)(nil), errors.New("database error"))
	req = &model.LoginRequest{Username: "erroruser", Password: "password123"}
	_, err = userService.LoginUser(ctx, req)
	assert.Error(t, err)
	assert.Nil(t, user)

	mockRepo.AssertExpectations(t)
	mockChecker.AssertExpectations(t)
}

func TestUserService_HashPassword(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockChecker := new(MockPasswordChecker)
	userService := NewUserService(mockRepo, mockChecker)

	password := "password123"
	hashedPassword, err := userService.HashPassword(password)
	assert.NoError(t, err)
	assert.NotEmpty(t, hashedPassword)           // Check that hash is not empty
	assert.NotEqual(t, password, hashedPassword) // Check that hash is different from the original

	mockRepo.AssertExpectations(t)
	mockChecker.AssertExpectations(t)
}
