package middleware

import (
	"context"
	"sync"
	"time"

	"github.com/baditaflorin/go-auth-middleware/internal/config"
	"github.com/baditaflorin/go-auth-middleware/internal/errors"
	"github.com/baditaflorin/go-auth-middleware/internal/httpclient"
	"github.com/baditaflorin/go-auth-middleware/internal/logger"
	"github.com/baditaflorin/go-auth-middleware/internal/validator"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// AuthMiddleware handles authentication via external service
type AuthMiddleware struct {
	config         *config.Config
	client         *httpclient.Client
	validator      *validator.TokenValidator
	logger         *logger.Logger
	rateLimiter    *rate.Limiter
	metricsEnabled bool
	metrics        *Metrics
}

// Metrics holds authentication metrics
type Metrics struct {
	mu                sync.RWMutex
	TotalRequests     uint64
	SuccessfulAuths   uint64
	FailedAuths       uint64
	RateLimitHits     uint64
	CircuitBreakerHits uint64
	AverageLatencyMs  float64
	latencies         []float64
}

// New creates a new authentication middleware
func New(cfg *config.Config, log *logger.Logger) (*AuthMiddleware, error) {
	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, errors.NewConfigError(err)
	}

	// Create HTTP client
	client := httpclient.New(cfg, log)

	// Create token validator
	tokenValidator := validator.NewTokenValidator(cfg.MaxTokenLength)

	// Create rate limiter if enabled
	var rateLimiter *rate.Limiter
	if cfg.RateLimitEnabled {
		rateLimiter = rate.NewLimiter(rate.Limit(cfg.RateLimitRPS), cfg.RateLimitRPS)
	}

	return &AuthMiddleware{
		config:         cfg,
		client:         client,
		validator:      tokenValidator,
		logger:         log,
		rateLimiter:    rateLimiter,
		metricsEnabled: true,
		metrics:        &Metrics{},
	}, nil
}

// Handler returns the Gin middleware handler
func (am *AuthMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		// Increment request counter
		am.incrementMetric("total")

		// Check rate limit
		if am.config.RateLimitEnabled && !am.rateLimiter.Allow() {
			am.incrementMetric("rate_limit")
			am.logger.Warn("Rate limit exceeded", map[string]interface{}{
				"client_ip": c.ClientIP(),
			})
			err := errors.NewRateLimitError()
			am.sendError(c, err)
			return
		}

		// Extract auth header
		authHeader := c.GetHeader(am.config.TokenHeader)
		if authHeader == "" {
			am.incrementMetric("failed")
			am.logger.Debug("Missing auth header", map[string]interface{}{
				"header": am.config.TokenHeader,
			})
			err := errors.NewInvalidTokenError(nil)
			am.sendError(c, err)
			return
		}

		// Extract token from header
		token, err := validator.ExtractToken(authHeader, am.config.TokenPrefix)
		if err != nil {
			am.incrementMetric("failed")
			am.logger.Debug("Failed to extract token", map[string]interface{}{
				"error": err.Error(),
			})
			authErr := errors.NewInvalidTokenError(err)
			am.sendError(c, authErr)
			return
		}

		// Validate token format
		if err := am.validator.ValidateToken(token); err != nil {
			am.incrementMetric("failed")
			am.logger.Debug("Token validation failed", map[string]interface{}{
				"error": err.Error(),
			})
			authErr := errors.NewInvalidTokenError(err)
			am.sendError(c, authErr)
			return
		}

		// Validate token with auth service
		ctx := c.Request.Context()
		resp, err := am.client.ValidateToken(ctx, token)
		if err != nil {
			am.incrementMetric("failed")

			// Check for circuit breaker
			if authErr, ok := err.(*errors.AuthError); ok && authErr.Code == errors.ErrCodeCircuitOpen {
				am.incrementMetric("circuit_breaker")
			}

			am.logger.Error("Token validation failed", err, map[string]interface{}{
				"client_ip": c.ClientIP(),
			})

			// Send appropriate error
			if authErr, ok := err.(*errors.AuthError); ok {
				am.sendError(c, authErr)
			} else {
				am.sendError(c, errors.NewInternalError(err))
			}
			return
		}

		// Validation successful
		am.incrementMetric("success")
		duration := time.Since(startTime)
		am.recordLatency(duration)

		am.logger.Debug("Authentication successful", map[string]interface{}{
			"user_id":     resp.UserID,
			"duration_ms": duration.Milliseconds(),
		})

		// Set user information in context
		c.Set(am.config.UserIDKey, resp.UserID)
		c.Set("auth_data", resp.Data)

		c.Next()
	}
}

// sendError sends a consistent error response
func (am *AuthMiddleware) sendError(c *gin.Context, err *errors.AuthError) {
	c.JSON(err.StatusCode, gin.H{
		"error": err.UserMessage(),
		"code":  err.Code,
	})
	c.Abort()
}

// incrementMetric increments a metric counter
func (am *AuthMiddleware) incrementMetric(metric string) {
	if !am.metricsEnabled {
		return
	}

	am.metrics.mu.Lock()
	defer am.metrics.mu.Unlock()

	switch metric {
	case "total":
		am.metrics.TotalRequests++
	case "success":
		am.metrics.SuccessfulAuths++
	case "failed":
		am.metrics.FailedAuths++
	case "rate_limit":
		am.metrics.RateLimitHits++
	case "circuit_breaker":
		am.metrics.CircuitBreakerHits++
	}
}

// recordLatency records request latency
func (am *AuthMiddleware) recordLatency(duration time.Duration) {
	if !am.metricsEnabled {
		return
	}

	am.metrics.mu.Lock()
	defer am.metrics.mu.Unlock()

	latencyMs := float64(duration.Milliseconds())
	am.metrics.latencies = append(am.metrics.latencies, latencyMs)

	// Keep only last 1000 samples
	if len(am.metrics.latencies) > 1000 {
		am.metrics.latencies = am.metrics.latencies[1:]
	}

	// Calculate average
	var sum float64
	for _, l := range am.metrics.latencies {
		sum += l
	}
	am.metrics.AverageLatencyMs = sum / float64(len(am.metrics.latencies))
}

// GetMetrics returns current metrics
func (am *AuthMiddleware) GetMetrics() Metrics {
	am.metrics.mu.RLock()
	defer am.metrics.mu.RUnlock()

	return Metrics{
		TotalRequests:      am.metrics.TotalRequests,
		SuccessfulAuths:    am.metrics.SuccessfulAuths,
		FailedAuths:        am.metrics.FailedAuths,
		RateLimitHits:      am.metrics.RateLimitHits,
		CircuitBreakerHits: am.metrics.CircuitBreakerHits,
		AverageLatencyMs:   am.metrics.AverageLatencyMs,
	}
}

// ResetMetrics resets all metrics
func (am *AuthMiddleware) ResetMetrics() {
	am.metrics.mu.Lock()
	defer am.metrics.mu.Unlock()

	am.metrics.TotalRequests = 0
	am.metrics.SuccessfulAuths = 0
	am.metrics.FailedAuths = 0
	am.metrics.RateLimitHits = 0
	am.metrics.CircuitBreakerHits = 0
	am.metrics.AverageLatencyMs = 0
	am.metrics.latencies = nil
}

// HealthCheck performs a health check
func (am *AuthMiddleware) HealthCheck(ctx context.Context) error {
	return am.client.HealthCheck(ctx)
}

// GetCircuitBreakerState returns the current circuit breaker state
func (am *AuthMiddleware) GetCircuitBreakerState() string {
	return am.client.GetCircuitBreakerState()
}
