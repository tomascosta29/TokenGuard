// File: /home/fcosta/CostaAuth/./internal/service/user_service.go
package service

import (
	"context"
	"fmt"
	"log"

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
	log.Println("NewUserService: Creating new user service")
	return &UserService{userRepo: userRepo, passwordChecker: passwordChecker}
}

// ... (RegisterUser function - see below for changes) ...
func (s *UserService) RegisterUser(ctx context.Context, req *model.RegisterRequest) (*model.User, error) {
	log.Printf("RegisterUser: Registering user with username %s", req.Username)
	// Check if the username or email already exists
	existingUser, err := s.userRepo.GetUserByUsername(ctx, req.Username)
	if err != nil {
		log.Printf("RegisterUser: Error getting user by username: %v", err)
		return nil, err
	}
	if existingUser != nil {
		log.Printf("RegisterUser: Username %s already exists", req.Username)
		return nil, fmt.Errorf("username already exists")
	}
	existingUser, err = s.userRepo.GetUserByEmail(ctx, req.Email) // add GetUserByEmail to repo interface + impl
	if err != nil {
		log.Printf("RegisterUser: Error getting user by email: %v", err)
		return nil, err
	}
	if existingUser != nil {
		log.Printf("RegisterUser: Email %s already exists", req.Email)
		return nil, fmt.Errorf("email already exists")
	}

	// Hash the password
	hashedPassword, err := s.HashPassword(req.Password)
	if err != nil {
		log.Printf("RegisterUser: Error hashing password: %v", err)
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
		log.Printf("RegisterUser: Error creating user: %v", err)
		return nil, err
	}

	log.Printf("RegisterUser: User %s registered successfully", req.Username)
	return newUser, nil
}

func (s *UserService) LoginUser(ctx context.Context, req *model.LoginRequest) (*model.User, error) {
	log.Printf("LoginUser: Logging in user with username %s", req.Username)
	user, err := s.userRepo.GetUserByUsername(ctx, req.Username)
	if err != nil {
		log.Printf("LoginUser: Error getting user by username: %v", err)
		return nil, err
	}
	if user == nil {
		log.Println("LoginUser: Invalid credentials")
		return nil, fmt.Errorf("invalid credentials")
	}

	// Use the injected PasswordChecker
	if !s.passwordChecker.CheckPasswordHash(req.Password, user.PasswordHash) {
		log.Println("LoginUser: Invalid credentials")
		return nil, fmt.Errorf("invalid credentials")
	}

	log.Printf("LoginUser: User %s logged in successfully", req.Username)
	return user, nil
}

// HashPassword hashes a password using bcrypt
func (s *UserService) HashPassword(password string) (string, error) {
	log.Println("HashPassword: Hashing password")
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("HashPassword: Error generating hash: %v", err)
		return "", err
	}
	log.Println("HashPassword: Password hashed successfully")
	return string(hashedPassword), nil
}
