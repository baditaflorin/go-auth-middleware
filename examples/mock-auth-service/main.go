package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

// MockAuthService provides a simple auth service for testing
func main() {
	router := gin.Default()

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Token validation endpoint
	router.GET("/validate", func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		// Check for valid token format
		if authHeader == "" {
			c.JSON(401, gin.H{"error": "Missing authorization header"})
			return
		}

		// Simple validation: accept any token starting with "Bearer valid"
		if len(authHeader) > 13 && authHeader[:13] == "Bearer valid" {
			c.JSON(200, gin.H{
				"user_id": "user123",
				"email":   "user@example.com",
				"roles":   []string{"user", "admin"},
			})
			return
		}

		// Reject invalid tokens
		c.JSON(401, gin.H{"error": "Invalid token"})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	log.Printf("Mock auth service starting on port %s", port)
	log.Printf("Valid tokens: Any token starting with 'validtoken'")
	if err := router.Run(":" + port); err != nil {
		log.Fatal(err)
	}
}
