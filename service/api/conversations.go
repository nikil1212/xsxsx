package api

import (
	"database/sql"
	"errors"
)

// Conversation represents a conversation entity.
type Conversation struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// CreateConversation adds a new conversation to the database.
func CreateConversation(db *sql.DB, name string) (int64, error) {
	if name == "" {
		return 0, errors.New("conversation name cannot be empty")
	}

	result, err := db.Exec("INSERT INTO conversations (name) VALUES (?)", name)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// GetConversations retrieves all conversations from the database.
func GetConversations(db *sql.DB) ([]Conversation, error) {
	rows, err := db.Query("SELECT id, name FROM conversations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var conversations []Conversation
	for rows.Next() {
		var c Conversation
		if err := rows.Scan(&c.ID, &c.Name); err != nil {
			return nil, err
		}
		conversations = append(conversations, c)
	}

	return conversations, nil
}
