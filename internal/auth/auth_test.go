package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	if token == "" {
		t.Fatal("Expected non-empty token")
	}

	// Validate the token we just created
	validatedUserID, err := ValidateJWT(token, tokenSecret)
	if err != nil {
		t.Fatalf("ValidateJWT failed: %v", err)
	}

	if validatedUserID != userID {
		t.Fatalf("Expected userID %v, got %v", userID, validatedUserID)
	}
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret"
	expiresIn := -time.Hour // Negative duration means already expired

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	// Try to validate the expired token
	_, err = ValidateJWT(token, tokenSecret)
	if err == nil {
		t.Fatal("Expected error for expired token, got nil")
	}
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret"
	wrongSecret := "wrong-secret"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	// Try to validate with wrong secret
	_, err = ValidateJWT(token, wrongSecret)
	if err == nil {
		t.Fatal("Expected error for wrong secret, got nil")
	}
}

func TestValidateJWT_InvalidToken(t *testing.T) {
	tokenSecret := "test-secret"
	invalidToken := "invalid.token.here"

	// Try to validate invalid token
	_, err := ValidateJWT(invalidToken, tokenSecret)
	if err == nil {
		t.Fatal("Expected error for invalid token, got nil")
	}
}

func TestValidateJWT_EmptyToken(t *testing.T) {
	tokenSecret := "test-secret"

	// Try to validate empty token
	_, err := ValidateJWT("", tokenSecret)
	if err == nil {
		t.Fatal("Expected error for empty token, got nil")
	}
}

func TestGetBearerToken(t *testing.T) {
	// Test valid bearer token
	headers := http.Header{}
	headers.Set("Authorization", "Bearer valid-token-123")
	
	token, err := GetBearerToken(headers)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if token != "valid-token-123" {
		t.Fatalf("Expected 'valid-token-123', got: %s", token)
	}
}

func TestGetBearerToken_NoHeader(t *testing.T) {
	headers := http.Header{}
	
	_, err := GetBearerToken(headers)
	if err == nil {
		t.Fatal("Expected error for missing authorization header")
	}
	if err.Error() != "authorization header not found" {
		t.Fatalf("Expected 'authorization header not found', got: %s", err.Error())
	}
}

func TestGetBearerToken_NoBearerPrefix(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "InvalidPrefix valid-token-123")
	
	_, err := GetBearerToken(headers)
	if err == nil {
		t.Fatal("Expected error for missing 'Bearer ' prefix")
	}
	if err.Error() != "authorization header must start with 'Bearer '" {
		t.Fatalf("Expected 'authorization header must start with 'Bearer '', got: %s", err.Error())
	}
}

func TestGetBearerToken_EmptyToken(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer ")
	
	_, err := GetBearerToken(headers)
	if err == nil {
		t.Fatal("Expected error for empty token")
	}
	if err.Error() != "token not found in authorization header" {
		t.Fatalf("Expected 'token not found in authorization header', got: %s", err.Error())
	}
}

func TestGetBearerToken_WhitespaceHandling(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer   token-with-spaces  ")
	
	token, err := GetBearerToken(headers)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if token != "token-with-spaces" {
		t.Fatalf("Expected 'token-with-spaces', got: %s", token)
	}
}

func TestMakeRefreshToken(t *testing.T) {
	token, err := MakeRefreshToken()
	if err != nil {
		t.Fatalf("MakeRefreshToken failed: %v", err)
	}

	// Check that token is 64 characters long (32 bytes * 2 hex chars per byte)
	if len(token) != 64 {
		t.Fatalf("Expected token length 64, got %d", len(token))
	}

	// Check that token contains only hex characters
	for _, char := range token {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			t.Fatalf("Token contains non-hex character: %c", char)
		}
	}

	// Test that multiple calls produce different tokens
	token2, err := MakeRefreshToken()
	if err != nil {
		t.Fatalf("MakeRefreshToken failed: %v", err)
	}

	if token == token2 {
		t.Fatal("Expected different tokens, got same token")
	}
}