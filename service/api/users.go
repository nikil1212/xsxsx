package api

import (
	"database/sql"
	"errors"
)

// User represents a user entity.
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

// GetUserByID fetches a user by ID from the database.
func GetUserByID(db *sql.DB, userID int) (*User, error) {
	var user User

	// Query the database
	err := db.QueryRow("SELECT id, username FROM users WHERE id = ?", userID).
		Scan(&user.ID, &user.Username)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // User not found
		}
		return nil, err // Other errors
	}

	return &user, nil
}
