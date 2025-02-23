package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3" // Import the SQLite driver
	"github.com/tomascosta29/CostaAuth/internal/model"
	// Import the SQLite driver
)

type SQLiteUserRepository struct {
	db *sql.DB
}

func NewSQLiteUserRepository(dbPath string) (*SQLiteUserRepository, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Ensure the database is properly closed on application exit.  Good practice.
	//  In a real app, you might want to handle graceful shutdowns more carefully.
	// go func() {
	// 	<-ctx.Done() //usually you have a ctx passed down to main
	// 	db.Close()
	// }()

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Create the users table if it doesn't exist
	if err := createUsersTable(db); err != nil {
		return nil, fmt.Errorf("failed to create users table: %w", err)
	}

	return &SQLiteUserRepository{db: db}, nil
}

func createUsersTable(db *sql.DB) error {
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
	return err
}

func (r *SQLiteUserRepository) CreateUser(ctx context.Context, user *model.User) error {
	user.ID = uuid.New()
	user.CreatedAt = time.Now().Unix()
	user.UpdatedAt = user.CreatedAt
	user.IsActive = true // default

	stmt, err := r.db.PrepareContext(ctx, "INSERT INTO users (id, username, email, password_hash, created_at, updated_at, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return fmt.Errorf("failed to prepare insert statement: %w", err)
	}
	defer stmt.Close() // Important: Close the statement after use

	_, err = stmt.ExecContext(ctx, user.ID, user.Username, user.Email, user.PasswordHash, user.CreatedAt, user.UpdatedAt, user.IsActive)
	if err != nil {
		return fmt.Errorf("failed to insert user: %w", err)
	}

	return nil
}

func (r *SQLiteUserRepository) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	user := &model.User{}
	row := r.db.QueryRowContext(ctx, "SELECT id, username, email, password_hash, created_at, updated_at, is_active FROM users WHERE username = ?", username)
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt, &user.IsActive)
	if err == sql.ErrNoRows {
		return nil, nil // User not found, return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to query user by username: %w", err)
	}
	return user, nil
}

func (r *SQLiteUserRepository) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	user := &model.User{}
	row := r.db.QueryRowContext(ctx, "SELECT id, username, email, password_hash, created_at, updated_at, is_active FROM users WHERE email = ?", email)
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt, &user.IsActive)
	if err == sql.ErrNoRows {
		return nil, nil // User not found, return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to query user by email: %w", err)
	}
	return user, nil
}

func (r *SQLiteUserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	user := &model.User{}
	row := r.db.QueryRowContext(ctx, "SELECT id, username, email, password_hash, created_at, updated_at, is_active FROM users WHERE id = ?", id)
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt, &user.IsActive)
	if err == sql.ErrNoRows {
		return nil, nil // User not found
	} else if err != nil {
		return nil, fmt.Errorf("failed to query user by ID: %w", err)
	}
	return user, nil
}
