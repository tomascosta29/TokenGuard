// File: /home/fcosta/CostaAuth/./internal/repository/user_repository.go
package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/tomascosta29/CostaAuth/internal/model"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user *model.User) error
	GetUserByUsername(ctx context.Context, username string) (*model.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*model.User, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
}
