package httpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/baditaflorin/go-auth-middleware/internal/config"
	"github.com/baditaflorin/go-auth-middleware/internal/errors"
	"github.com/baditaflorin/go-auth-middleware/internal/logger"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/sony/gobreaker"
)

// Client wraps an HTTP client with resilience features
type Client struct {
	httpClient     *retryablehttp.Client
	circuitBreaker *gobreaker.CircuitBreaker
	logger         *logger.Logger
	config         *config.Config
}

// New creates a new resilient HTTP client
func New(cfg *config.Config, log *logger.Logger) *Client {
	// Create retryable HTTP client
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = cfg.MaxRetries
	retryClient.RetryWaitMin = cfg.RetryWaitMin
	retryClient.RetryWaitMax = cfg.RetryWaitMax
	retryClient.Logger = nil // Disable retryablehttp's default logging

	// Configure underlying HTTP client
	retryClient.HTTPClient = &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// Create circuit breaker
	cbSettings := gobreaker.Settings{
		Name:        "auth-service",
		MaxRequests: cfg.CircuitBreakerMaxRequests,
		Interval:    cfg.CircuitBreakerInterval,
		Timeout:     cfg.CircuitBreakerTimeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= cfg.CircuitBreakerThreshold
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			log.Warn("Circuit breaker state changed", map[string]interface{}{
				"name": name,
				"from": from.String(),
				"to":   to.String(),
			})
		},
	}
	cb := gobreaker.NewCircuitBreaker(cbSettings)

	return &Client{
		httpClient:     retryClient,
		circuitBreaker: cb,
		logger:         log,
		config:         cfg,
	}
}

// ValidateTokenRequest represents a token validation request
type ValidateTokenRequest struct {
	Token string
}

// ValidateTokenResponse represents a token validation response
type ValidateTokenResponse struct {
	Valid  bool                   `json:"valid"`
	UserID string                 `json:"user_id,omitempty"`
	Data   map[string]interface{} `json:"data,omitempty"`
}

// ValidateToken validates a token against the auth service
func (c *Client) ValidateToken(ctx context.Context, token string) (*ValidateTokenResponse, error) {
	startTime := time.Now()

	// Execute with circuit breaker
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		return c.doValidateToken(ctx, token)
	})

	duration := time.Since(startTime)
	c.logger.Debug("Token validation completed", map[string]interface{}{
		"duration_ms": duration.Milliseconds(),
		"error":       err != nil,
	})

	if err != nil {
		// Check if circuit breaker error
		if err == gobreaker.ErrOpenState {
			return nil, errors.NewCircuitOpenError()
		}
		return nil, err
	}

	return result.(*ValidateTokenResponse), nil
}

func (c *Client) doValidateToken(ctx context.Context, token string) (*ValidateTokenResponse, error) {
	// Build URL
	url := c.config.AuthServiceURL + c.config.ValidateEndpoint

	// Create request
	req, err := retryablehttp.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		c.logger.Error("Failed to create request", err, map[string]interface{}{
			"url": url,
		})
		return nil, errors.NewInternalError(fmt.Errorf("failed to create request: %w", err))
	}

	// Set auth header
	req.Header.Set(c.config.TokenHeader, c.config.TokenPrefix+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "go-auth-middleware/1.0")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error("Request to auth service failed", err, map[string]interface{}{
			"url": url,
		})
		return nil, errors.NewAuthServiceUnavailableError(fmt.Errorf("auth service request failed: %w", err))
	}
	defer resp.Body.Close()

	// Limit response body size to prevent memory exhaustion
	limitedBody := io.LimitReader(resp.Body, 1024*1024) // 1MB max

	// Check status code
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		c.logger.Debug("Token validation rejected", map[string]interface{}{
			"status_code": resp.StatusCode,
		})
		return nil, errors.NewUnauthorizedError(fmt.Errorf("auth service returned %d", resp.StatusCode))
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(limitedBody)
		c.logger.Error("Unexpected response from auth service", nil, map[string]interface{}{
			"status_code": resp.StatusCode,
			"body":        string(bodyBytes),
		})
		return nil, errors.NewAuthServiceUnavailableError(fmt.Errorf("unexpected status code: %d", resp.StatusCode))
	}

	// Parse response
	var result map[string]interface{}
	if err := json.NewDecoder(limitedBody).Decode(&result); err != nil {
		c.logger.Error("Failed to parse auth service response", err, nil)
		return nil, errors.NewInternalError(fmt.Errorf("failed to parse response: %w", err))
	}

	// Build response
	response := &ValidateTokenResponse{
		Valid: true,
		Data:  result,
	}

	// Extract user ID if present
	if userID, ok := result[c.config.UserIDKey]; ok {
		if userIDStr, ok := userID.(string); ok {
			response.UserID = userIDStr
		}
	}

	return response, nil
}

// HealthCheck performs a health check on the auth service
func (c *Client) HealthCheck(ctx context.Context) error {
	url := c.config.AuthServiceURL + "/health"

	req, err := retryablehttp.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	// Use a shorter timeout for health checks
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req = req.WithContext(healthCtx)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	return nil
}

// GetCircuitBreakerState returns the current circuit breaker state
func (c *Client) GetCircuitBreakerState() string {
	return c.circuitBreaker.State().String()
}
