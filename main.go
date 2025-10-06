package main

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"io/ioutil"
	"bytes"
	"encoding/json"
	_ "github.com/lib/pq"
	"os"
	"log"
	"sort"
	"github.com/PassZ/http-server/internal/database"
	"database/sql"
	_ "github.com/joho/godotenv/autoload"
	"github.com/google/uuid"
	"github.com/PassZ/http-server/internal/auth"
	"time"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries *database.Queries
	platform string
	jwtSecret string
	polkaKey string
}

type userRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type updateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type polkaWebhookRequest struct {
	Event string `json:"event"`
	Data  struct {
		UserID string `json:"user_id"`
	} `json:"data"`
}

type chirpRequest struct {
	Body string `json:"body"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func main() {
	// Connect to chirpy postgresql database
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Read environment variables
	platform := os.Getenv("PLATFORM")
	jwtSecret := os.Getenv("JWT_SECRET")
	polkaKey := os.Getenv("POLKA_KEY")
	
	// Create a shared apiConfig instance
	cfg := &apiConfig{fileserverHits: atomic.Int32{}, dbQueries: database.New(db), platform: platform, jwtSecret: jwtSecret, polkaKey: polkaKey}
	
	// Create a new http.ServeMux
	mux := http.NewServeMux()
	mux.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("./")))))

	// Handle the /healthz endpoint
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("OK"))
	})

	// Handle the /metrics endpoint
	mux.HandleFunc("GET /admin/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// content type is html
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		adminMetrics := fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", cfg.fileserverHits.Load())
		w.Write([]byte(adminMetrics))
	})

	// Handle the /reset endpoint
	mux.HandleFunc("POST /admin/reset", func(w http.ResponseWriter, r *http.Request) {
		// Check if platform is dev
		if cfg.platform != "dev" {
			w.WriteHeader(http.StatusForbidden)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write([]byte("Forbidden"))
			return
		}
		
		// Reset file server hits
		cfg.fileserverHits.Store(0)
		
		// Delete all users from database
		err := cfg.dbQueries.DeleteAllUsers(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write([]byte("Internal Server Error"))
			return
		}
		
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("Reset"))
	})


	// Handle the /users endpoint
	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		// Read the request body
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Parse the JSON request
		var userReq userRequest
		err = json.Unmarshal(body, &userReq)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Validate required fields
		if userReq.Email == "" || userReq.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Email and password are required"}`))
			return
		}

		// Hash the password
		hashedPassword, err := auth.HashPassword(userReq.Password)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Create user in database
		user, err := cfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{
			Email:          userReq.Email,
			HashedPassword: hashedPassword,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Return the user data
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		
		response := map[string]interface{}{
			"id":             user.ID,
			"created_at":     user.CreatedAt,
			"updated_at":     user.UpdatedAt,
			"email":          user.Email,
			"is_chirpy_red":  user.IsChirpyRed,
		}
		
		jsonResponse, err := json.Marshal(response)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}
		
		w.Write(jsonResponse)
	})

	// Handle the /login endpoint
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		// Read the request body
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Parse the JSON request
		var userReq userRequest
		err = json.Unmarshal(body, &userReq)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Validate required fields
		if userReq.Email == "" || userReq.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Email and password are required"}`))
			return
		}

		// Get user by email
		user, err := cfg.dbQueries.GetUserByEmail(r.Context(), userReq.Email)
		if err != nil {
			// Check if it's a "no rows" error (user not found)
			if err.Error() == "sql: no rows in result set" {
				w.WriteHeader(http.StatusUnauthorized)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Write([]byte(`{"error": "Incorrect email or password"}`))
				return
			}
			// Other database errors
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Check password
		passwordMatch, err := auth.CheckPasswordHash(userReq.Password, user.HashedPassword)
		if err != nil || !passwordMatch {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Incorrect email or password"}`))
			return
		}

		// Create access token (1 hour expiration)
		accessToken, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Hour)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Create refresh token
		refreshToken, err := auth.MakeRefreshToken()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Store refresh token in database (60 days expiration)
		refreshExpiresAt := time.Now().Add(60 * 24 * time.Hour) // 60 days
		_, err = cfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
			Token:     refreshToken,
			UserID:    user.ID,
			ExpiresAt: refreshExpiresAt,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Return the user data with tokens
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		
		response := map[string]interface{}{
			"id":             user.ID,
			"created_at":     user.CreatedAt,
			"updated_at":     user.UpdatedAt,
			"email":          user.Email,
			"is_chirpy_red":  user.IsChirpyRed,
			"token":          accessToken,
			"refresh_token":  refreshToken,
		}
		
		jsonResponse, err := json.Marshal(response)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}
		
		w.Write(jsonResponse)
	})

	// Handle the /refresh endpoint
	mux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {
		// Get refresh token from Authorization header
		tokenString, err := auth.GetBearerToken(r.Header)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Unauthorized"}`))
			return
		}

		// Look up user from refresh token
		user, err := cfg.dbQueries.GetUserFromRefreshToken(r.Context(), tokenString)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Unauthorized"}`))
			return
		}

		// Create new access token (1 hour expiration)
		accessToken, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Hour)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Return the new access token
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		
		response := map[string]interface{}{
			"token": accessToken,
		}
		
		jsonResponse, err := json.Marshal(response)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}
		
		w.Write(jsonResponse)
	})

	// Handle the /revoke endpoint
	mux.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, r *http.Request) {
		// Get refresh token from Authorization header
		tokenString, err := auth.GetBearerToken(r.Header)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Unauthorized"}`))
			return
		}

		// Revoke the refresh token
		err = cfg.dbQueries.RevokeRefreshToken(r.Context(), tokenString)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Return 204 No Content
		w.WriteHeader(http.StatusNoContent)
	})

	// Handle the PUT /users endpoint
	mux.HandleFunc("PUT /api/users", func(w http.ResponseWriter, r *http.Request) {
		// Authenticate user with JWT
		tokenString, err := auth.GetBearerToken(r.Header)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Unauthorized"}`))
			return
		}

		userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Unauthorized"}`))
			return
		}

		// Read the request body
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Parse the JSON request
		var updateReq updateUserRequest
		err = json.Unmarshal(body, &updateReq)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Validate required fields
		if updateReq.Email == "" || updateReq.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Email and password are required"}`))
			return
		}

		// Hash the new password
		hashedPassword, err := auth.HashPassword(updateReq.Password)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Update user in database
		updatedUser, err := cfg.dbQueries.UpdateUser(r.Context(), database.UpdateUserParams{
			Email:          updateReq.Email,
			HashedPassword: hashedPassword,
			ID:             userID,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Return the updated user data (without password)
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		
		response := map[string]interface{}{
			"id":             updatedUser.ID,
			"created_at":     updatedUser.CreatedAt,
			"updated_at":     updatedUser.UpdatedAt,
			"email":          updatedUser.Email,
			"is_chirpy_red":  updatedUser.IsChirpyRed,
		}
		
		jsonResponse, err := json.Marshal(response)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}
		
		w.Write(jsonResponse)
	})

	// Handle the /chirps endpoint
	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		// Authenticate user with JWT
		tokenString, err := auth.GetBearerToken(r.Header)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Unauthorized"}`))
			return
		}

		userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Unauthorized"}`))
			return
		}

		// Read the request body
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Parse the JSON request
		var chirpReq chirpRequest
		err = json.Unmarshal(body, &chirpReq)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Check if the chirp body is 140 characters long or less
		if len(chirpReq.Body) > 140 {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Chirp is too long"}`))
			return
		}

		// Replace 'kerfuffle', 'sharbert', and 'fornax' with '****' (case insensitive)
		cleanedBody := chirpReq.Body
		cleanedBody = string(bytes.ReplaceAll([]byte(cleanedBody), []byte("kerfuffle"), []byte("****")))
		cleanedBody = string(bytes.ReplaceAll([]byte(cleanedBody), []byte("Kerfuffle"), []byte("****")))
		cleanedBody = string(bytes.ReplaceAll([]byte(cleanedBody), []byte("sharbert"), []byte("****")))
		cleanedBody = string(bytes.ReplaceAll([]byte(cleanedBody), []byte("Sharbert"), []byte("****")))
		cleanedBody = string(bytes.ReplaceAll([]byte(cleanedBody), []byte("fornax"), []byte("****")))
		cleanedBody = string(bytes.ReplaceAll([]byte(cleanedBody), []byte("Fornax"), []byte("****")))

		// Create chirp in database
		chirp, err := cfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
			Body:   cleanedBody,
			UserID: userID,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Return the chirp data
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		
		response := map[string]interface{}{
			"id":         chirp.ID,
			"created_at": chirp.CreatedAt,
			"updated_at": chirp.UpdatedAt,
			"body":       chirp.Body,
			"user_id":    chirp.UserID,
		}
		
		jsonResponse, err := json.Marshal(response)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}
		
		w.Write(jsonResponse)
	})

	// Handle the GET /chirps endpoint
	mux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		// Check for author_id query parameter
		authorIDStr := r.URL.Query().Get("author_id")
		
		var chirps []database.Chirp
		var err error
		
		if authorIDStr != "" {
			// Parse author_id to UUID
			authorID, err := uuid.Parse(authorIDStr)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Write([]byte(`{"error": "Invalid author_id format"}`))
				return
			}
			
			// Get chirps by author
			chirps, err = cfg.dbQueries.GetChirpsByAuthor(r.Context(), authorID)
		} else {
			// Get all chirps
			chirps, err = cfg.dbQueries.GetChirps(r.Context())
		}
		
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Convert chirps to response format
		response := make([]map[string]interface{}, 0, len(chirps))
		for _, chirp := range chirps {
			response = append(response, map[string]interface{}{
				"id":         chirp.ID,
				"created_at": chirp.CreatedAt,
				"updated_at": chirp.UpdatedAt,
				"body":       chirp.Body,
				"user_id":    chirp.UserID,
			})
		}

		// Handle sorting
		sortParam := r.URL.Query().Get("sort")
		if sortParam == "desc" {
			// Sort by created_at in descending order
			sort.Slice(response, func(i, j int) bool {
				return response[i]["created_at"].(time.Time).After(response[j]["created_at"].(time.Time))
			})
		} else {
			// Default to ascending order (asc or any other value)
			sort.Slice(response, func(i, j int) bool {
				return response[i]["created_at"].(time.Time).Before(response[j]["created_at"].(time.Time))
			})
		}

		// Return the chirps data
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		
		jsonResponse, err := json.Marshal(response)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}
		
		w.Write(jsonResponse)
	})

	// Handle the GET /chirps/{chirpID} endpoint
	mux.HandleFunc("GET /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		// Get chirpID from path parameter
		chirpIDStr := r.PathValue("chirpID")
		
		// Parse chirpID to UUID
		chirpID, err := uuid.Parse(chirpIDStr)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Chirp not found"}`))
			return
		}

		// Get chirp from database
		chirp, err := cfg.dbQueries.GetChirpByID(r.Context(), chirpID)
		if err != nil {
			// Check if it's a "no rows" error (chirp not found)
			if err.Error() == "sql: no rows in result set" {
				w.WriteHeader(http.StatusNotFound)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Write([]byte(`{"error": "Chirp not found"}`))
				return
			}
			// Other database errors
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Return the chirp data
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		
		response := map[string]interface{}{
			"id":         chirp.ID,
			"created_at": chirp.CreatedAt,
			"updated_at": chirp.UpdatedAt,
			"body":       chirp.Body,
			"user_id":    chirp.UserID,
		}
		
		jsonResponse, err := json.Marshal(response)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}
		
		w.Write(jsonResponse)
	})

	// Handle the POST /api/polka/webhooks endpoint
	mux.HandleFunc("POST /api/polka/webhooks", func(w http.ResponseWriter, r *http.Request) {
		// Validate API key
		apiKey, err := auth.GetAPIKey(r.Header)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Unauthorized"}`))
			return
		}

		// Check if the API key matches the expected one
		if apiKey != cfg.polkaKey {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Unauthorized"}`))
			return
		}

		// Parse the webhook request
		var webhookReq polkaWebhookRequest
		err = json.NewDecoder(r.Body).Decode(&webhookReq)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Invalid request body"}`))
			return
		}

		// Check if the event is user.upgraded
		if webhookReq.Event != "user.upgraded" {
			// We don't care about other events, return 204
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Parse the user ID
		userID, err := uuid.Parse(webhookReq.Data.UserID)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Invalid user ID"}`))
			return
		}

		// Upgrade the user to Chirpy Red
		_, err = cfg.dbQueries.UpgradeUserToChirpyRed(r.Context(), userID)
		if err != nil {
			// Check if it's a "no rows" error (user not found)
			if err.Error() == "sql: no rows in result set" {
				w.WriteHeader(http.StatusNotFound)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Write([]byte(`{"error": "User not found"}`))
				return
			}
			// Other database errors
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Success - return 204 No Content
		w.WriteHeader(http.StatusNoContent)
	})

	// Handle the DELETE /chirps/{chirpID} endpoint
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		// Authenticate user with JWT
		tokenString, err := auth.GetBearerToken(r.Header)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Unauthorized"}`))
			return
		}

		userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Unauthorized"}`))
			return
		}

		// Get chirpID from path parameter
		chirpIDStr := r.PathValue("chirpID")
		
		// Parse chirpID to UUID
		chirpID, err := uuid.Parse(chirpIDStr)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Chirp not found"}`))
			return
		}

		// First, check if the chirp exists and get its details
		chirp, err := cfg.dbQueries.GetChirpByID(r.Context(), chirpID)
		if err != nil {
			// Check if it's a "no rows" error (chirp not found)
			if err.Error() == "sql: no rows in result set" {
				w.WriteHeader(http.StatusNotFound)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Write([]byte(`{"error": "Chirp not found"}`))
				return
			}
			// Other database errors
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Check if the user is the author of the chirp
		if chirp.UserID != userID {
			w.WriteHeader(http.StatusForbidden)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Forbidden"}`))
			return
		}

		// Delete the chirp
		err = cfg.dbQueries.DeleteChirp(r.Context(), database.DeleteChirpParams{
			ID:     chirpID,
			UserID: userID,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		// Return 204 No Content on successful deletion
		w.WriteHeader(http.StatusNoContent)
	})

	// Create a new http.Server struct
	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	
	// Use the server's ListenAndServe to start the server
	fmt.Println("Starting server on port 8080")
	err = server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
	}
}
