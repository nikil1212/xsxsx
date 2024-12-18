package api

import (
	"database/sql"
	"errors"
	"time"
)

// Message represents a message entity.
type Message struct {
	ID             int64     `json:"id"`
	ConversationID int64     `json:"conversation_id"`
	UserID         int64     `json:"user_id"`
	Content        string    `json:"content"`
	CreatedAt      time.Time `json:"created_at"`
}

// AddMessage adds a new message to a conversation.
func AddMessage(db *sql.DB, conversationID, userID int64, content string) (int64, error) {
	if content == "" {
		return 0, errors.New("message content cannot be empty")
	}

	result, err := db.Exec("INSERT INTO messages (conversation_id, user_id, content) VALUES (?, ?, ?)", conversationID, userID, content)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// GetMessages retrieves all messages for a specific conversation.
func GetMessages(db *sql.DB, conversationID int64) ([]Message, error) {
	rows, err := db.Query("SELECT id, conversation_id, user_id, content, created_at FROM messages WHERE conversation_id = ?", conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.ConversationID, &m.UserID, &m.Content, &m.CreatedAt); err != nil {
			return nil, err
		}
		messages = append(messages, m)
	}

	return messages, nil
}
