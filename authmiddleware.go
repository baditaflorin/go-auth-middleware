// File: authmiddleware.go

package authmiddleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Config holds the configuration for the AuthMiddleware
type Config struct {
	AuthServiceURL   string
	ValidateEndpoint string
	TokenPrefix      string
	TokenHeader      string
	UserIDKey        string
}

// DefaultConfig provides default configuration values
var DefaultConfig = Config{
	ValidateEndpoint: "/validate",
	TokenPrefix:      "Bearer ",
	TokenHeader:      "Authorization",
	UserIDKey:        "user_id",
}

// AuthMiddleware provides a Gin middleware for token-based authentication.
type AuthMiddleware struct {
	config Config
}

// New creates a new instance of AuthMiddleware
func New(config Config) *AuthMiddleware {
	// Use default values for any unspecified fields
	if config.ValidateEndpoint == "" {
		config.ValidateEndpoint = DefaultConfig.ValidateEndpoint
	}
	if config.TokenPrefix == "" {
		config.TokenPrefix = DefaultConfig.TokenPrefix
	}
	if config.TokenHeader == "" {
		config.TokenHeader = DefaultConfig.TokenHeader
	}
	if config.UserIDKey == "" {
		config.UserIDKey = DefaultConfig.UserIDKey
	}
	return &AuthMiddleware{
		config: config,
	}
}

// Middleware returns a Gin HandlerFunc that can be used as middleware
func (am *AuthMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader(am.config.TokenHeader)
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": am.config.TokenHeader + " header required"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, am.config.TokenPrefix)

		req, _ := http.NewRequest("GET", am.config.AuthServiceURL+am.config.ValidateEndpoint, nil)
		req.Header.Set(am.config.TokenHeader, am.config.TokenPrefix+tokenString)

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

		userID, ok := result[am.config.UserIDKey].(string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid response from auth service"})
			c.Abort()
			return
		}

		c.Set("userID", userID)
		c.Next()
	}
}
