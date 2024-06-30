package authmiddleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Config holds the configuration for the AuthMiddleware
type Config struct {
	AuthServiceURL string
}

// AuthMiddleware provides a Gin middleware for token-based authentication.
type AuthMiddleware struct {
	config Config
}

// New creates a new instance of AuthMiddleware
func New(config Config) *AuthMiddleware {
	return &AuthMiddleware{
		config: config,
	}
}

// Middleware returns a Gin HandlerFunc that can be used as middleware
func (am *AuthMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		req, _ := http.NewRequest("GET", am.config.AuthServiceURL+"/validate", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to communicate with auth service"})
			c.Abort()
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse auth service response"})
			c.Abort()
			return
		}

		userID, ok := result["user_id"].(string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid response from auth service"})
			c.Abort()
			return
		}

		c.Set("userID", userID)
		c.Next()
	}
}
