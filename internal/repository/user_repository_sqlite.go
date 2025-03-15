// File: TokenGuard/./internal/repository/user_repository_sqlite.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3" // Import the SQLite driver
	"github.com/tomascosta29/TokenGuard/internal/model"
	// Import the SQLite driver
)

type SQLiteUserRepository struct {
	db *sql.DB
}

func NewSQLiteUserRepository(dbPath string) (*SQLiteUserRepository, error) {
	log.Printf("NewSQLiteUserRepository: Opening SQLite database at %s", dbPath)
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Printf("NewSQLiteUserRepository: Failed to open database: %v", err)
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Ensure the database is properly closed on application exit.  Good practice.
	//  In a real app, you might want to handle graceful shutdowns more carefully.
	// go func() {
	// 	<-ctx.Done() //usually you have a ctx passed down to main
	// 	db.Close()
	// }()

	if err := db.Ping(); err != nil {
		log.Printf("NewSQLiteUserRepository: Failed to ping database: %v", err)
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Create the users table if it doesn't exist
	if err := createUsersTable(db); err != nil {
		log.Printf("NewSQLiteUserRepository: Failed to create users table: %v", err)
		return nil, fmt.Errorf("failed to create users table: %w", err)
	}

	log.Println("NewSQLiteUserRepository: SQLite user repository initialized.")
	return &SQLiteUserRepository{db: db}, nil
}

func createUsersTable(db *sql.DB) error {
	log.Println("createUsersTable: Creating users table if not exists")
	createTableSQL := `
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			is_active INTEGER NOT NULL
		);
	`
	_, err := db.Exec(createTableSQL)
	if err != nil {
		log.Printf("createUsersTable: Failed to execute SQL: %v", err)
		return err
	}
	log.Println("createUsersTable: Users table created or already exists")
	return err
}

func (r *SQLiteUserRepository) CreateUser(ctx context.Context, user *model.User) error {
	log.Printf("CreateUser: Creating user with username %s", user.Username)
	user.ID = uuid.New()
	user.CreatedAt = time.Now().Unix()
	user.UpdatedAt = user.CreatedAt
	user.IsActive = true // default

	stmt, err := r.db.PrepareContext(ctx, "INSERT INTO users (id, username, email, password_hash, created_at, updated_at, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		log.Printf("CreateUser: Failed to prepare insert statement: %v", err)
		return fmt.Errorf("failed to prepare insert statement: %w", err)
	}
	defer stmt.Close() // Important: Close the statement after use

	_, err = stmt.ExecContext(ctx, user.ID, user.Username, user.Email, user.PasswordHash, user.CreatedAt, user.UpdatedAt, user.IsActive)
	if err != nil {
		log.Printf("CreateUser: Failed to insert user: %v", err)
		return fmt.Errorf("failed to insert user: %w", err)
	}

	log.Printf("CreateUser: User %s created successfully", user.Username)
	return nil
}

func (r *SQLiteUserRepository) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	log.Printf("GetUserByUsername: Getting user by username %s", username)
	user := &model.User{}
	row := r.db.QueryRowContext(ctx, "SELECT id, username, email, password_hash, created_at, updated_at, is_active FROM users WHERE username = ?", username)
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt, &user.IsActive)
	if err == sql.ErrNoRows {
		log.Printf("GetUserByUsername: User %s not found", username)
		return nil, nil // User not found, return nil, nil
	} else if err != nil {
		log.Printf("GetUserByUsername: Failed to query user by username: %v", err)
		return nil, fmt.Errorf("failed to query user by username: %w", err)
	}
	log.Printf("GetUserByUsername: User %s retrieved successfully", username)
	return user, nil
}

func (r *SQLiteUserRepository) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	log.Printf("GetUserByEmail: Getting user by email %s", email)
	user := &model.User{}
	row := r.db.QueryRowContext(ctx, "SELECT id, username, email, password_hash, created_at, updated_at, is_active FROM users WHERE email = ?", email)
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt, &user.IsActive)
	if err == sql.ErrNoRows {
		log.Printf("GetUserByEmail: User with email %s not found", email)
		return nil, nil // User not found, return nil, nil
	} else if err != nil {
		log.Printf("GetUserByEmail: Failed to query user by email: %v", err)
		return nil, fmt.Errorf("failed to query user by email: %w", err)
	}
	log.Printf("GetUserByEmail: User with email %s retrieved successfully", email)
	return user, nil
}

func (r *SQLiteUserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	log.Printf("GetUserByID: Getting user by ID %s", id)
	user := &model.User{}
	row := r.db.QueryRowContext(ctx, "SELECT id, username, email, password_hash, created_at, updated_at, is_active FROM users WHERE id = ?", id)
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt, &user.IsActive)
	if err == sql.ErrNoRows {
		log.Printf("GetUserByID: User with ID %s not found", id)
		return nil, nil // User not found
	} else if err != nil {
		log.Printf("GetUserByID: Failed to query user by ID: %v", err)
		return nil, fmt.Errorf("failed to query user by ID: %w", err)
	}
	log.Printf("GetUserByID: User with ID %s retrieved successfully", id)
	return user, nil
}
