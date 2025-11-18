package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the auth middleware
type Config struct {
	// Auth Service Configuration
	AuthServiceURL   string        `json:"auth_service_url"`
	ValidateEndpoint string        `json:"validate_endpoint"`
	TokenHeader      string        `json:"token_header"`
	TokenPrefix      string        `json:"token_prefix"`
	UserIDKey        string        `json:"user_id_key"`

	// HTTP Client Configuration
	Timeout          time.Duration `json:"timeout"`
	MaxRetries       int           `json:"max_retries"`
	RetryWaitMin     time.Duration `json:"retry_wait_min"`
	RetryWaitMax     time.Duration `json:"retry_wait_max"`

	// Circuit Breaker Configuration
	CircuitBreakerMaxRequests    uint32        `json:"circuit_breaker_max_requests"`
	CircuitBreakerInterval       time.Duration `json:"circuit_breaker_interval"`
	CircuitBreakerTimeout        time.Duration `json:"circuit_breaker_timeout"`
	CircuitBreakerThreshold      uint32        `json:"circuit_breaker_threshold"`

	// Rate Limiting
	RateLimitEnabled bool `json:"rate_limit_enabled"`
	RateLimitRPS     int  `json:"rate_limit_rps"`

	// Security
	MaxTokenLength   int  `json:"max_token_length"`
	ValidateURL      bool `json:"validate_url"`

	// Logging
	LogLevel         string `json:"log_level"`
	LogFormat        string `json:"log_format"` // json or text
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		ValidateEndpoint:             "/validate",
		TokenHeader:                  "Authorization",
		TokenPrefix:                  "Bearer ",
		UserIDKey:                    "user_id",
		Timeout:                      10 * time.Second,
		MaxRetries:                   3,
		RetryWaitMin:                 100 * time.Millisecond,
		RetryWaitMax:                 2 * time.Second,
		CircuitBreakerMaxRequests:    3,
		CircuitBreakerInterval:       60 * time.Second,
		CircuitBreakerTimeout:        30 * time.Second,
		CircuitBreakerThreshold:      5,
		RateLimitEnabled:             true,
		RateLimitRPS:                 100,
		MaxTokenLength:               8192,
		ValidateURL:                  true,
		LogLevel:                     "info",
		LogFormat:                    "json",
	}
}

// LoadFromEnv loads configuration from environment variables
// It uses DefaultConfig as base and overrides with env vars when present
func LoadFromEnv() (*Config, error) {
	cfg := DefaultConfig()

	// Required: AuthServiceURL
	authURL := os.Getenv("AUTH_SERVICE_URL")
	if authURL == "" {
		return nil, errors.New("AUTH_SERVICE_URL environment variable is required")
	}
	cfg.AuthServiceURL = authURL

	// Optional overrides
	if val := os.Getenv("AUTH_VALIDATE_ENDPOINT"); val != "" {
		cfg.ValidateEndpoint = val
	}
	if val := os.Getenv("AUTH_TOKEN_HEADER"); val != "" {
		cfg.TokenHeader = val
	}
	if val := os.Getenv("AUTH_TOKEN_PREFIX"); val != "" {
		cfg.TokenPrefix = val
	}
	if val := os.Getenv("AUTH_USER_ID_KEY"); val != "" {
		cfg.UserIDKey = val
	}

	// HTTP Client timeouts
	if val := os.Getenv("AUTH_TIMEOUT"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil {
			return nil, fmt.Errorf("invalid AUTH_TIMEOUT: %w", err)
		}
		cfg.Timeout = d
	}

	if val := os.Getenv("AUTH_MAX_RETRIES"); val != "" {
		n, err := strconv.Atoi(val)
		if err != nil {
			return nil, fmt.Errorf("invalid AUTH_MAX_RETRIES: %w", err)
		}
		cfg.MaxRetries = n
	}

	if val := os.Getenv("AUTH_RETRY_WAIT_MIN"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil {
			return nil, fmt.Errorf("invalid AUTH_RETRY_WAIT_MIN: %w", err)
		}
		cfg.RetryWaitMin = d
	}

	if val := os.Getenv("AUTH_RETRY_WAIT_MAX"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil {
			return nil, fmt.Errorf("invalid AUTH_RETRY_WAIT_MAX: %w", err)
		}
		cfg.RetryWaitMax = d
	}

	// Circuit Breaker
	if val := os.Getenv("AUTH_CB_MAX_REQUESTS"); val != "" {
		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid AUTH_CB_MAX_REQUESTS: %w", err)
		}
		cfg.CircuitBreakerMaxRequests = uint32(n)
	}

	if val := os.Getenv("AUTH_CB_INTERVAL"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil {
			return nil, fmt.Errorf("invalid AUTH_CB_INTERVAL: %w", err)
		}
		cfg.CircuitBreakerInterval = d
	}

	if val := os.Getenv("AUTH_CB_TIMEOUT"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil {
			return nil, fmt.Errorf("invalid AUTH_CB_TIMEOUT: %w", err)
		}
		cfg.CircuitBreakerTimeout = d
	}

	if val := os.Getenv("AUTH_CB_THRESHOLD"); val != "" {
		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid AUTH_CB_THRESHOLD: %w", err)
		}
		cfg.CircuitBreakerThreshold = uint32(n)
	}

	// Rate Limiting
	if val := os.Getenv("AUTH_RATE_LIMIT_ENABLED"); val != "" {
		enabled, err := strconv.ParseBool(val)
		if err != nil {
			return nil, fmt.Errorf("invalid AUTH_RATE_LIMIT_ENABLED: %w", err)
		}
		cfg.RateLimitEnabled = enabled
	}

	if val := os.Getenv("AUTH_RATE_LIMIT_RPS"); val != "" {
		n, err := strconv.Atoi(val)
		if err != nil {
			return nil, fmt.Errorf("invalid AUTH_RATE_LIMIT_RPS: %w", err)
		}
		cfg.RateLimitRPS = n
	}

	// Security
	if val := os.Getenv("AUTH_MAX_TOKEN_LENGTH"); val != "" {
		n, err := strconv.Atoi(val)
		if err != nil {
			return nil, fmt.Errorf("invalid AUTH_MAX_TOKEN_LENGTH: %w", err)
		}
		cfg.MaxTokenLength = n
	}

	if val := os.Getenv("AUTH_VALIDATE_URL"); val != "" {
		enabled, err := strconv.ParseBool(val)
		if err != nil {
			return nil, fmt.Errorf("invalid AUTH_VALIDATE_URL: %w", err)
		}
		cfg.ValidateURL = enabled
	}

	// Logging
	if val := os.Getenv("AUTH_LOG_LEVEL"); val != "" {
		cfg.LogLevel = val
	}

	if val := os.Getenv("AUTH_LOG_FORMAT"); val != "" {
		cfg.LogFormat = val
	}

	return cfg, nil
}

// Validate checks that the configuration is valid and safe
func (c *Config) Validate() error {
	var errs []error

	// Validate AuthServiceURL
	if c.AuthServiceURL == "" {
		errs = append(errs, errors.New("AuthServiceURL cannot be empty"))
	} else if c.ValidateURL {
		parsedURL, err := url.Parse(c.AuthServiceURL)
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid AuthServiceURL: %w", err))
		} else {
			if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
				errs = append(errs, fmt.Errorf("AuthServiceURL must use http or https scheme, got: %s", parsedURL.Scheme))
			}
			if parsedURL.Host == "" {
				errs = append(errs, errors.New("AuthServiceURL must have a host"))
			}
		}
	}

	// Validate endpoint
	if c.ValidateEndpoint == "" {
		errs = append(errs, errors.New("ValidateEndpoint cannot be empty"))
	}

	// Validate headers
	if c.TokenHeader == "" {
		errs = append(errs, errors.New("TokenHeader cannot be empty"))
	}

	// Validate timeouts
	if c.Timeout <= 0 {
		errs = append(errs, errors.New("Timeout must be positive"))
	}
	if c.Timeout > 5*time.Minute {
		errs = append(errs, errors.New("Timeout cannot exceed 5 minutes (potential DoS vector)"))
	}

	// Validate retries
	if c.MaxRetries < 0 {
		errs = append(errs, errors.New("MaxRetries cannot be negative"))
	}
	if c.MaxRetries > 10 {
		errs = append(errs, errors.New("MaxRetries cannot exceed 10 (excessive retry attempts)"))
	}

	if c.RetryWaitMin <= 0 {
		errs = append(errs, errors.New("RetryWaitMin must be positive"))
	}
	if c.RetryWaitMax <= 0 {
		errs = append(errs, errors.New("RetryWaitMax must be positive"))
	}
	if c.RetryWaitMin > c.RetryWaitMax {
		errs = append(errs, errors.New("RetryWaitMin cannot exceed RetryWaitMax"))
	}

	// Validate circuit breaker
	if c.CircuitBreakerInterval <= 0 {
		errs = append(errs, errors.New("CircuitBreakerInterval must be positive"))
	}
	if c.CircuitBreakerTimeout <= 0 {
		errs = append(errs, errors.New("CircuitBreakerTimeout must be positive"))
	}

	// Validate rate limiting
	if c.RateLimitEnabled && c.RateLimitRPS <= 0 {
		errs = append(errs, errors.New("RateLimitRPS must be positive when rate limiting is enabled"))
	}
	if c.RateLimitRPS > 10000 {
		errs = append(errs, errors.New("RateLimitRPS cannot exceed 10000 (unrealistic rate limit)"))
	}

	// Validate security settings
	if c.MaxTokenLength <= 0 {
		errs = append(errs, errors.New("MaxTokenLength must be positive"))
	}
	if c.MaxTokenLength > 1024*1024 {
		errs = append(errs, errors.New("MaxTokenLength cannot exceed 1MB (potential DoS vector)"))
	}

	// Validate log settings
	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if !validLogLevels[c.LogLevel] {
		errs = append(errs, fmt.Errorf("invalid LogLevel: %s (must be debug, info, warn, or error)", c.LogLevel))
	}

	validLogFormats := map[string]bool{
		"json": true, "text": true,
	}
	if !validLogFormats[c.LogFormat] {
		errs = append(errs, fmt.Errorf("invalid LogFormat: %s (must be json or text)", c.LogFormat))
	}

	if len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}

	return nil
}

// ValidationError represents multiple validation errors
type ValidationError struct {
	Errors []error
}

func (e *ValidationError) Error() string {
	if len(e.Errors) == 0 {
		return "validation failed"
	}
	if len(e.Errors) == 1 {
		return e.Errors[0].Error()
	}
	msg := fmt.Sprintf("validation failed with %d errors:", len(e.Errors))
	for i, err := range e.Errors {
		msg += fmt.Sprintf("\n  %d. %s", i+1, err.Error())
	}
	return msg
}
