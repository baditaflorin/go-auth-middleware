package main

import (
	"log"
	"os"

	"github.com/baditaflorin/go-auth-middleware/pkg/authmiddleware"
	"github.com/gin-gonic/gin"
)

func main() {
	// Load configuration from environment variables
	authMiddleware, err := authmiddleware.NewFromEnv()
	if err != nil {
		log.Fatalf("Failed to create auth middleware: %v", err)
	}

	// Create Gin router
	router := gin.Default()

	// Public endpoint (no authentication required)
	router.GET("/public", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "This is a public endpoint",
		})
	})

	// Protected endpoints (authentication required)
	protected := router.Group("/api")
	protected.Use(authMiddleware.Handler())
	{
		protected.GET("/profile", func(c *gin.Context) {
			userID := c.GetString("user_id")
			authData := c.MustGet("auth_data")

			c.JSON(200, gin.H{
				"message": "This is a protected endpoint",
				"user_id": userID,
				"data":    authData,
			})
		})

		protected.GET("/dashboard", func(c *gin.Context) {
			userID := c.GetString("user_id")
			c.JSON(200, gin.H{
				"message": "Welcome to your dashboard",
				"user_id": userID,
			})
		})
	}

	// Metrics endpoint
	router.GET("/metrics", func(c *gin.Context) {
		metrics := authMiddleware.GetMetrics()
		c.JSON(200, metrics)
	})

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		err := authMiddleware.HealthCheck(c.Request.Context())
		if err != nil {
			c.JSON(503, gin.H{
				"status": "unhealthy",
				"error":  err.Error(),
			})
			return
		}

		c.JSON(200, gin.H{
			"status":          "healthy",
			"circuit_breaker": authMiddleware.GetCircuitBreakerState(),
		})
	})

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatal(err)
	}
}
