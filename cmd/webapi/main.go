package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"

	"github.com/nikiljay/WasaHW/cmd/webapi/middleware"
	"github.com/nikiljay/WasaHW/service/api"
	"github.com/nikiljay/WasaHW/service/database"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte("myjwtkey")

func init() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET environment variable is not set")
	}
	log.Printf("JWT_SECRET loaded: %s", secret) // Debug only, remove in production
	jwtSecret = []byte(secret)
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// main is the entry point of the application.
func main() {
	// Reading the DSN from environment variables
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		log.Fatal("MYSQL_DSN environment variable is required")
	}

	// Initialize the database connection
	database.InitializeDatabase(dsn)

	// Running the migrations
	database.RunMigrations(database.DB)

	// Initialize the router using the Gorilla Mux package.
	router := mux.NewRouter()

	// Apply middleware
	router.Use(middleware.CORSHandler)
	router.Use(middleware.LoggingMiddleware)
	router.Use(middleware.ErrorHandlingMiddleware)

	// Set up API routes by calling the setupRoutes function.
	setupRoutes(router)

	// Start the server on port 8080 and attach the router.
	log.Println("Starting server on :8080...")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// setupRoutes maps API endpoints to their respective handlers
func setupRoutes(router *mux.Router) {
	// Unprotected routes
	router.HandleFunc("/session", sessionHandler).Methods("POST")
	router.HandleFunc("/users", registerUserHandler).Methods("POST")
	router.HandleFunc("/login", loginHandler).Methods("POST")

	// Define the protected subrouter
	protected := router.PathPrefix("/").Subrouter()

	// Protected routes
	protected.HandleFunc("/conversations", createConversationHandler).Methods("POST")
	protected.HandleFunc("/conversations", getConversationsHandler).Methods("GET")
	protected.HandleFunc("/conversations/{id}", getConversationHandler).Methods("GET")
	protected.HandleFunc("/conversations/{id}", updateConversationHandler).Methods("PUT")
	protected.HandleFunc("/conversations/{id}", deleteConversationHandler).Methods("DELETE")
	protected.HandleFunc("/users/{id}", getUserHandler).Methods("GET")
	protected.Use(middleware.AuthenticationMiddleware)

	// Messages
	protected.HandleFunc("/conversations/{id}/messages", addMessageHandler).Methods("POST")
	protected.HandleFunc("/conversations/{id}/messages", getMessagesHandler).Methods("GET")
	protected.HandleFunc("/conversations/{id}/messages/{messageId}", getMessageHandler).Methods("GET")
	protected.HandleFunc("/conversations/{id}/messages/{messageId}", deleteMessageHandler).Methods("DELETE")
	protected.HandleFunc("/conversations/{id}/messages/{messageId}/comment", commentMessageHandler).Methods("POST")
	protected.HandleFunc("/conversations/{id}/messages/{messageId}/uncomment", uncommentMessageHandler).Methods("DELETE")

	// Groups
	protected.HandleFunc("/groups", createGroupHandler).Methods("POST")
	protected.HandleFunc("/groups/{groupId}/name", updateGroupNameHandler).Methods("PUT")
	protected.HandleFunc("/groups/{groupId}/photo", updateGroupPhotoHandler).Methods("PUT")
	protected.HandleFunc("/groups/{groupId}/add", addUserToGroupHandler).Methods("POST")
	protected.HandleFunc("/groups/{groupId}/leave", leaveGroupHandler).Methods("DELETE")

	// User
	protected.HandleFunc("/user/photo", updateUserPhotoHandler).Methods("PUT")

	// Protected route example
	protected.HandleFunc("/protected", protectedHandler).Methods("GET")

	// Apply middleware only to the protected routes
	protected.Use(middleware.AuthenticationMiddleware)

	// Global middleware for all routes
	router.Use(middleware.CORSHandler)
	router.Use(middleware.LoggingMiddleware)
	router.Use(middleware.ErrorHandlingMiddleware)
}

// Handler implementations (placeholders)
func sessionHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var storedHash string
	err := database.DB.QueryRow("SELECT password_hash FROM users WHERE username = ?", creds.Username).Scan(&storedHash)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
			if err != nil {
				http.Error(w, "Failed to create user", http.StatusInternalServerError)
				return
			}
			_, err = database.DB.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", creds.Username, hashedPassword)
			if err != nil {
				http.Error(w, "Failed to create user", http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	} else {
		if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(creds.Password)); err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func registerUserHandler(w http.ResponseWriter, r *http.Request) {
	type RegisterRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Insert the user into the database
	_, err = database.DB.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", req.Username, string(hashedPassword))
	if err != nil {
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	type LoginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Retrieve user from the database
	var storedHash string
	err := database.DB.QueryRow("SELECT password_hash FROM users WHERE username = ?", req.Username).Scan(&storedHash)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Compare passwords
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate a JWT token
	token, err := generateJWT(req.Username)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func generateJWT(username string) (string, error) {
	// Define token expiration time
	expirationTime := time.Now().Add(24 * time.Hour)

	// Create claims
	claims := &jwt.StandardClaims{
		Subject:   username,
		ExpiresAt: expirationTime.Unix(),
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(middleware.UserContextKey)
	if user == nil {
		http.Error(w, "No user information found", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello, " + user.(string)))
}

func createConversationHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	id, err := api.CreateConversation(database.DB, req.Name)
	if err != nil {
		http.Error(w, "Failed to create conversation", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":   id,
		"name": req.Name,
	})
}

func getConversationsHandler(w http.ResponseWriter, r *http.Request) {
	conversations, err := api.GetConversations(database.DB)
	if err != nil {
		http.Error(w, "Failed to fetch conversations", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(conversations)
}

func getConversationHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"id": "1", "name": "Sample Conversation"}`))
}

func updateConversationHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Conversation updated successfully"}`))
}

func deleteConversationHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Conversation deleted successfully"}`))
}

//getUserHandler handles GET /users/{id} requests.

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from the URL path
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Fetch user details from the service layer
	user, err := api.GetUserByID(database.DB, userID)
	if err != nil {
		http.Error(w, "Failed to fetch user", http.StatusInternalServerError)
		return
	}

	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func addMessageHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	conversationID, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, "Invalid conversation ID", http.StatusBadRequest)
		return
	}

	var req struct {
		UserID  int64  `json:"user_id"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	messageID, err := api.AddMessage(database.DB, conversationID, req.UserID, req.Content)
	if err != nil {
		http.Error(w, "Failed to add message", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id": messageID,
	})
}

func getMessagesHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	conversationID, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil {
		log.Printf("Error parsing conversation ID: %v", err)
		http.Error(w, "Invalid conversation ID", http.StatusBadRequest)
		return
	}

	messages, err := api.GetMessages(database.DB, conversationID)
	if err != nil {
		log.Printf("Error fetching messages for conversation %d: %v", conversationID, err)
		http.Error(w, "Failed to fetch messages", http.StatusInternalServerError)
		return
	}

	if len(messages) == 0 {
		log.Printf("No messages found for conversation %d", conversationID)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func getMessageHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"id": "1", "content": "Sample Message"}`))
}

func deleteMessageHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Message deleted successfully"}`))
}

func commentMessageHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"message": "Comment added successfully"}`))
}

func uncommentMessageHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Comment removed successfully"}`))
}

func createGroupHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"groupId": "123", "message": "Group created successfully"}`))
}

func updateGroupNameHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Group name updated successfully"}`))
}

func updateGroupPhotoHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Group photo updated successfully"}`))
}

func addUserToGroupHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "User added to group successfully"}`))
}

func leaveGroupHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Left group successfully"}`))
}

func updateUserPhotoHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "User photo updated successfully"}`))
}
