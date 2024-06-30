# Go Auth Middleware

This module provides a reusable authentication middleware for Gin-based Go applications. It validates JWT tokens by making a request to an authentication service.

## Installation

```bash
go get github.com/yourusername/go-auth-middleware
```

## Usage
Here's how to use the middleware in your Gin application:
```bash
import (
"github.com/gin-gonic/gin"
"github.com/yourusername/go-auth-middleware"
)

func main() {
r := gin.Default()

    // Create a new instance of AuthMiddleware with configuration
    authMiddleware := authmiddleware.New(authmiddleware.Config{
        AuthServiceURL: "http://auth-service-url", // Use your actual auth service URL here
    })

    // Use the middleware for protected routes
    protected := r.Group("/")
    protected.Use(authMiddleware.Middleware())
    {
        protected.GET("/profile", getProfile)
    }

    r.Run(":8080")
}

func getProfile(c *gin.Context) {
// The user ID is now available in the context
userID, _ := c.Get("userID")
// Use the userID...
}
```

## Configuration
The AuthMiddleware can be configured with the following options:

`AuthServiceURL`: The URL of the authentication service used to validate tokens

You can extend the `Config` struct with additional options as needed for your specific use case.
