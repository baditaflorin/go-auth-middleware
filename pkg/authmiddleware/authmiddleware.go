package authmiddleware

import (
	"context"
	"os"

	"github.com/baditaflorin/go-auth-middleware/internal/config"
	"github.com/baditaflorin/go-auth-middleware/internal/logger"
	"github.com/baditaflorin/go-auth-middleware/internal/middleware"
	"github.com/gin-gonic/gin"
)

// AuthMiddleware is the public interface for the authentication middleware
type AuthMiddleware struct {
	internal *middleware.AuthMiddleware
	logger   *logger.Logger
}

// Config is the public configuration interface
type Config = config.Config

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return config.DefaultConfig()
}

// New creates a new authentication middleware with the provided configuration
func New(cfg *Config) (*AuthMiddleware, error) {
	// Create logger
	log := logger.New(cfg.LogLevel, cfg.LogFormat, os.Stdout)

	// Create internal middleware
	internal, err := middleware.New(cfg, log)
	if err != nil {
		return nil, err
	}

	return &AuthMiddleware{
		internal: internal,
		logger:   log,
	}, nil
}

// NewFromEnv creates a new authentication middleware from environment variables
func NewFromEnv() (*AuthMiddleware, error) {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return nil, err
	}

	return New(cfg)
}

// Handler returns the Gin middleware handler function
func (am *AuthMiddleware) Handler() gin.HandlerFunc {
	return am.internal.Handler()
}

// Metrics represents authentication metrics
type Metrics struct {
	TotalRequests      uint64  `json:"total_requests"`
	SuccessfulAuths    uint64  `json:"successful_auths"`
	FailedAuths        uint64  `json:"failed_auths"`
	RateLimitHits      uint64  `json:"rate_limit_hits"`
	CircuitBreakerHits uint64  `json:"circuit_breaker_hits"`
	AverageLatencyMs   float64 `json:"average_latency_ms"`
}

// GetMetrics returns current authentication metrics
func (am *AuthMiddleware) GetMetrics() Metrics {
	internal := am.internal.GetMetrics()
	return Metrics{
		TotalRequests:      internal.TotalRequests,
		SuccessfulAuths:    internal.SuccessfulAuths,
		FailedAuths:        internal.FailedAuths,
		RateLimitHits:      internal.RateLimitHits,
		CircuitBreakerHits: internal.CircuitBreakerHits,
		AverageLatencyMs:   internal.AverageLatencyMs,
	}
}

// ResetMetrics resets all metrics counters
func (am *AuthMiddleware) ResetMetrics() {
	am.internal.ResetMetrics()
}

// HealthCheck performs a health check against the auth service
func (am *AuthMiddleware) HealthCheck(ctx context.Context) error {
	return am.internal.HealthCheck(ctx)
}

// GetCircuitBreakerState returns the current circuit breaker state
func (am *AuthMiddleware) GetCircuitBreakerState() string {
	return am.internal.GetCircuitBreakerState()
}
