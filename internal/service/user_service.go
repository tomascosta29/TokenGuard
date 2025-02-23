package service

import (
	"context"
	"fmt"

	"github.com/tomascosta29/CostaAuth/internal/model"
	"github.com/tomascosta29/CostaAuth/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

type UserServiceInterface interface {
	RegisterUser(ctx context.Context, req *model.RegisterRequest) (*model.User, error)
	LoginUser(ctx context.Context, req *model.LoginRequest) (*model.User, error)
	HashPassword(password string) (string, error) // keep this here
}

type UserService struct {
	userRepo        repository.UserRepository
	passwordChecker PasswordChecker // Add the dependency
}

// Update the constructor to accept the PasswordChecker
func NewUserService(userRepo repository.UserRepository, passwordChecker PasswordChecker) *UserService {
	return &UserService{userRepo: userRepo, passwordChecker: passwordChecker}
}

// ... (RegisterUser function - see below for changes) ...
func (s *UserService) RegisterUser(ctx context.Context, req *model.RegisterRequest) (*model.User, error) {
	// Check if the username or email already exists
	existingUser, err := s.userRepo.GetUserByUsername(ctx, req.Username)
	if err != nil {
		return nil, err
	}
	if existingUser != nil {
		return nil, fmt.Errorf("username already exists")
	}
	existingUser, err = s.userRepo.GetUserByEmail(ctx, req.Email) // add GetUserByEmail to repo interface + impl
	if err != nil {
		return nil, err
	}
	if existingUser != nil {
		return nil, fmt.Errorf("email already exists")
	}

	// Hash the password
	hashedPassword, err := s.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	// Create the user
	newUser := &model.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: hashedPassword,
		IsActive:     true, // Or false, if you require email verification
	}

	err = s.userRepo.CreateUser(ctx, newUser)
	if err != nil {
		return nil, err
	}

	return newUser, nil
}

func (s *UserService) LoginUser(ctx context.Context, req *model.LoginRequest) (*model.User, error) {
	user, err := s.userRepo.GetUserByUsername(ctx, req.Username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Use the injected PasswordChecker
	if !s.passwordChecker.CheckPasswordHash(req.Password, user.PasswordHash) {
		return nil, fmt.Errorf("invalid credentials")
	}

	return user, nil
}

// HashPassword hashes a password using bcrypt
func (s *UserService) HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}
