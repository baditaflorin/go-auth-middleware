# Go Auth Middleware

A production-ready, secure authentication middleware for Go web applications using the Gin framework. This middleware delegates authentication to an external HTTP service with built-in resilience, security hardening, and comprehensive testing.

## Features

### Security
- **Fully parameterized queries** - No dynamic SQL construction
- **Input validation & sanitization** - All inputs validated against strict patterns
- **Non-leaking error messages** - Safe, minimal error responses to users
- **Token size limits** - Prevents DoS attacks via oversized tokens
- **Security test suite** - Tests for SQL injection, XSS, command injection, and more

### Resilience
- **Circuit breaker** - Automatically fails fast when auth service is down
- **Retry logic** - Configurable retry with exponential backoff
- **Request timeouts** - Prevents hanging requests
- **Rate limiting** - Token bucket algorithm for request throttling
- **Connection pooling** - Efficient HTTP client configuration

### Configuration
- **Environment-driven** - All settings via environment variables
- **Validation** - Configuration validated on startup with clear error messages
- **Sensible defaults** - Works out of the box with minimal configuration
- **Graceful failure** - Clear errors for missing/invalid configuration

### Code Quality
- **DRY/SOLID principles** - Clean, maintainable architecture
- **Single responsibility** - Small, focused components
- **Comprehensive tests** - Unit, integration, and security tests
- **High code coverage** - Well-tested codebase

### Observability
- **Structured logging** - JSON or text format logs
- **Metrics collection** - Request counts, latencies, failure rates
- **Health checks** - Built-in health check endpoints
- **Circuit breaker monitoring** - Track circuit breaker state

### GUI Test Harness
- **Configuration management** - Load/save configuration via web UI
- **Live testing** - Test tokens against real auth service
- **Response inspection** - View detailed API responses
- **Metrics dashboard** - Real-time metrics visualization

## Quick Start

### Installation

```bash
go get github.com/baditaflorin/go-auth-middleware
```

### Basic Usage

```go
package main

import (
    "log"
    "github.com/baditaflorin/go-auth-middleware/pkg/authmiddleware"
    "github.com/gin-gonic/gin"
)

func main() {
    // Create middleware from environment variables
    auth, err := authmiddleware.NewFromEnv()
    if err != nil {
        log.Fatal(err)
    }

    // Create router and apply middleware
    router := gin.Default()

    // Protected routes
    router.Use(auth.Handler())
    router.GET("/api/profile", func(c *gin.Context) {
        userID := c.GetString("user_id")
        c.JSON(200, gin.H{"user_id": userID})
    })

    router.Run(":8080")
}
```

### Environment Variables

Required:
```bash
AUTH_SERVICE_URL=http://localhost:8081  # URL of authentication service
```

Optional (with defaults):
```bash
AUTH_VALIDATE_ENDPOINT=/validate       # Validation endpoint path
AUTH_TOKEN_HEADER=Authorization         # Header containing auth token
AUTH_TOKEN_PREFIX="Bearer "             # Token prefix to strip
AUTH_USER_ID_KEY=user_id               # JSON key for user ID

# HTTP Client
AUTH_TIMEOUT=10s                        # Request timeout
AUTH_MAX_RETRIES=3                      # Max retry attempts
AUTH_RETRY_WAIT_MIN=100ms              # Min retry wait
AUTH_RETRY_WAIT_MAX=2s                 # Max retry wait

# Circuit Breaker
AUTH_CB_MAX_REQUESTS=3                  # Max requests in half-open state
AUTH_CB_INTERVAL=60s                    # Interval to clear counts
AUTH_CB_TIMEOUT=30s                     # Timeout before half-open
AUTH_CB_THRESHOLD=5                     # Consecutive failures to open

# Rate Limiting
AUTH_RATE_LIMIT_ENABLED=true           # Enable rate limiting
AUTH_RATE_LIMIT_RPS=100                # Requests per second

# Security
AUTH_MAX_TOKEN_LENGTH=8192             # Maximum token size
AUTH_VALIDATE_URL=true                 # Validate auth service URL

# Logging
AUTH_LOG_LEVEL=info                    # debug, info, warn, error
AUTH_LOG_FORMAT=json                   # json or text
```

## Running the Examples

### Using Make

```bash
# Install dependencies
make deps

# Run mock auth service
make run-mock-auth

# In another terminal, run example app
make run-example

# Or run the GUI test harness
make run-gui
```

### Using Docker Compose

```bash
# Start all services (app, mock auth, GUI)
docker-compose up

# Access services:
# - Example app: http://localhost:8080
# - Mock auth: http://localhost:8081
# - GUI harness: http://localhost:3000
```

### Manual Testing

```bash
# Start mock auth service
go run examples/mock-auth-service/main.go

# In another terminal, start example app
AUTH_SERVICE_URL=http://localhost:8081 go run examples/simple/main.go

# Test with curl
curl -H "Authorization: Bearer validtoken" http://localhost:8080/api/profile
```

## GUI Test Harness

The GUI test harness provides a web-based interface for testing and configuration:

1. Start the GUI: `make run-gui` or access via Docker at `http://localhost:3000`
2. Configure authentication settings
3. Test tokens in real-time
4. View metrics and health status
5. Inspect API responses

Features:
- Configuration validation before saving
- Live token validation against auth service
- Real-time metrics dashboard
- Circuit breaker state monitoring
- Health check integration

## Testing

```bash
# Run all tests
make test

# Run specific test suites
make test-unit          # Unit tests only
make test-integration   # Integration tests only
make test-security      # Security tests only

# Generate coverage report
make test-coverage      # Creates coverage.html
```

### Security Tests

The security test suite includes:
- SQL injection attempts
- XSS attacks
- Command injection
- Header injection
- Path traversal
- Null byte injection
- Unicode attacks
- Oversized payloads
- Error message leakage

## Architecture

```
go-auth-middleware/
├── cmd/
│   └── gui/                    # GUI test harness
├── internal/
│   ├── config/                 # Configuration management
│   ├── errors/                 # Error types & handling
│   ├── httpclient/             # Resilient HTTP client
│   ├── logger/                 # Structured logging
│   ├── middleware/             # Core middleware logic
│   └── validator/              # Input validation
├── pkg/
│   └── authmiddleware/         # Public API
├── tests/
│   ├── integration/            # Integration tests
│   └── security/               # Security tests
└── examples/
    ├── simple/                 # Basic usage example
    └── mock-auth-service/      # Mock auth for testing
```

## API Documentation

### Middleware Methods

#### `NewFromEnv() (*AuthMiddleware, error)`
Creates middleware from environment variables.

#### `New(cfg *Config) (*AuthMiddleware, error)`
Creates middleware with custom configuration.

#### `Handler() gin.HandlerFunc`
Returns the Gin middleware handler.

#### `GetMetrics() Metrics`
Returns current authentication metrics.

#### `ResetMetrics()`
Resets all metrics counters.

#### `HealthCheck(ctx context.Context) error`
Performs health check against auth service.

#### `GetCircuitBreakerState() string`
Returns current circuit breaker state.

## Production Deployment

### Best Practices

1. **Use HTTPS** - Always use HTTPS for auth service communication
2. **Set timeouts** - Configure appropriate timeouts for your use case
3. **Monitor metrics** - Track success rates and latencies
4. **Circuit breaker** - Tune circuit breaker settings for your traffic
5. **Rate limiting** - Set appropriate RPS limits
6. **Logging** - Use JSON format in production for log aggregation
7. **Non-root user** - Run containers as non-root (done by default)
8. **Secrets management** - Use secret management tools for sensitive config

### Kubernetes Deployment

Example deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: app
        image: myapp:latest
        env:
        - name: AUTH_SERVICE_URL
          valueFrom:
            configMapKeyRef:
              name: app-config
              key: auth-service-url
        - name: AUTH_LOG_FORMAT
          value: "json"
        resources:
          limits:
            memory: "128Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
```

## Security Best Practices

1. **Token validation** - All tokens are validated against strict character whitelists
2. **Size limits** - Tokens are limited to prevent memory exhaustion attacks
3. **Error messages** - Errors never expose internal implementation details
4. **Timeouts** - All requests have strict timeouts to prevent resource exhaustion
5. **Rate limiting** - Built-in rate limiting prevents abuse
6. **Circuit breaker** - Prevents cascading failures
7. **No SQL injection** - This middleware doesn't use SQL (delegates to external service)
8. **Input sanitization** - All inputs are sanitized before processing

## License

MIT License - see LICENSE file for details

## Support

- Issues: https://github.com/baditaflorin/go-auth-middleware/issues
