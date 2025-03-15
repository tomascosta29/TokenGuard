// File: TokenGuard/./internal/repository/user_repository_sqlite_test.go
package repository

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tomascosta29/TokenGuard/internal/model"

	_ "github.com/mattn/go-sqlite3"
)

// Helper function to create a test database
func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:") // In-memory database
	require.NoError(t, err)

	err = createUsersTable(db)
	require.NoError(t, err)

	return db
}

func TestSQLiteUserRepository_CreateUser(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	repo := &SQLiteUserRepository{db: db}
	ctx := context.Background()

	user := &model.User{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hashedpassword",
		IsActive:     true,
	}

	err := repo.CreateUser(ctx, user)
	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, user.ID) // Check that ID was generated
}

func TestSQLiteUserRepository_GetUserByUsername(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	repo := &SQLiteUserRepository{db: db}
	ctx := context.Background()

	// Create a test user first
	existingUser := &model.User{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hashedpassword",
		IsActive:     true,
	}
	err := repo.CreateUser(ctx, existingUser)
	require.NoError(t, err)

	// Retrieve the user by username
	retrievedUser, err := repo.GetUserByUsername(ctx, "testuser")
	assert.NoError(t, err)
	assert.NotNil(t, retrievedUser)
	assert.Equal(t, existingUser.Username, retrievedUser.Username)
	assert.Equal(t, existingUser.Email, retrievedUser.Email)
	assert.Equal(t, existingUser.PasswordHash, retrievedUser.PasswordHash)

	// Test case: User not found
	retrievedUser, err = repo.GetUserByUsername(ctx, "nonexistentuser")
	assert.NoError(t, err) // No error should occur
	assert.Nil(t, retrievedUser)
}

func TestSQLiteUserRepository_GetUserByEmail(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	repo := &SQLiteUserRepository{db: db}
	ctx := context.Background()

	// Create a test user first
	existingUser := &model.User{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hashedpassword",
		IsActive:     true,
	}
	err := repo.CreateUser(ctx, existingUser)
	require.NoError(t, err)

	// Retrieve the user by email
	retrievedUser, err := repo.GetUserByEmail(ctx, "test@example.com")
	assert.NoError(t, err)
	assert.NotNil(t, retrievedUser)
	assert.Equal(t, existingUser.Username, retrievedUser.Username)

	// Test case: User not found
	retrievedUser, err = repo.GetUserByEmail(ctx, "nonexistentuser@email.com")
	assert.NoError(t, err)
	assert.Nil(t, retrievedUser)
}

func TestSQLiteUserRepository_GetUserByID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	repo := &SQLiteUserRepository{db: db}
	ctx := context.Background()

	// Create a test user
	existingUser := &model.User{
		Username:     "testuser2",
		Email:        "test2@example.com",
		PasswordHash: "hashedpassword",
		IsActive:     true,
	}
	err := repo.CreateUser(ctx, existingUser)
	require.NoError(t, err)

	retrievedUser, err := repo.GetUserByID(ctx, existingUser.ID)
	assert.NoError(t, err)
	assert.NotNil(t, retrievedUser)
	assert.Equal(t, existingUser.ID, retrievedUser.ID)

	// Test case: User not found
	randomID := uuid.New()
	retrievedUser, err = repo.GetUserByID(ctx, randomID)
	assert.NoError(t, err)
	assert.Nil(t, retrievedUser)
}
