package config

import (
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ValidateEndpoint != "/validate" {
		t.Errorf("Expected ValidateEndpoint to be '/validate', got '%s'", cfg.ValidateEndpoint)
	}

	if cfg.TokenHeader != "Authorization" {
		t.Errorf("Expected TokenHeader to be 'Authorization', got '%s'", cfg.TokenHeader)
	}

	if cfg.Timeout != 10*time.Second {
		t.Errorf("Expected Timeout to be 10s, got %v", cfg.Timeout)
	}

	if cfg.MaxRetries != 3 {
		t.Errorf("Expected MaxRetries to be 3, got %d", cfg.MaxRetries)
	}
}

func TestLoadFromEnv(t *testing.T) {
	// Set up environment
	os.Setenv("AUTH_SERVICE_URL", "http://localhost:8080")
	os.Setenv("AUTH_VALIDATE_ENDPOINT", "/api/validate")
	os.Setenv("AUTH_TIMEOUT", "15s")
	os.Setenv("AUTH_MAX_RETRIES", "5")
	defer cleanupEnv()

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv failed: %v", err)
	}

	if cfg.AuthServiceURL != "http://localhost:8080" {
		t.Errorf("Expected AuthServiceURL to be 'http://localhost:8080', got '%s'", cfg.AuthServiceURL)
	}

	if cfg.ValidateEndpoint != "/api/validate" {
		t.Errorf("Expected ValidateEndpoint to be '/api/validate', got '%s'", cfg.ValidateEndpoint)
	}

	if cfg.Timeout != 15*time.Second {
		t.Errorf("Expected Timeout to be 15s, got %v", cfg.Timeout)
	}

	if cfg.MaxRetries != 5 {
		t.Errorf("Expected MaxRetries to be 5, got %d", cfg.MaxRetries)
	}
}

func TestLoadFromEnvMissingRequired(t *testing.T) {
	cleanupEnv()

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("Expected error when AUTH_SERVICE_URL is missing")
	}
}

func TestLoadFromEnvInvalidTimeout(t *testing.T) {
	os.Setenv("AUTH_SERVICE_URL", "http://localhost:8080")
	os.Setenv("AUTH_TIMEOUT", "invalid")
	defer cleanupEnv()

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("Expected error when AUTH_TIMEOUT is invalid")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		wantError bool
	}{
		{
			name:      "Valid config",
			config:    DefaultConfig(),
			wantError: true, // AuthServiceURL is required
		},
		{
			name: "Valid config with URL",
			config: &Config{
				AuthServiceURL:              "http://localhost:8080",
				ValidateEndpoint:            "/validate",
				TokenHeader:                 "Authorization",
				Timeout:                     10 * time.Second,
				MaxRetries:                  3,
				RetryWaitMin:                100 * time.Millisecond,
				RetryWaitMax:                2 * time.Second,
				CircuitBreakerInterval:      60 * time.Second,
				CircuitBreakerTimeout:       30 * time.Second,
				RateLimitEnabled:            true,
				RateLimitRPS:                100,
				MaxTokenLength:              8192,
				LogLevel:                    "info",
				LogFormat:                   "json",
			},
			wantError: false,
		},
		{
			name: "Empty AuthServiceURL",
			config: &Config{
				AuthServiceURL: "",
			},
			wantError: true,
		},
		{
			name: "Invalid URL scheme",
			config: &Config{
				AuthServiceURL:   "ftp://localhost:8080",
				ValidateEndpoint: "/validate",
				TokenHeader:      "Authorization",
				Timeout:          10 * time.Second,
				RetryWaitMin:     100 * time.Millisecond,
				RetryWaitMax:     2 * time.Second,
				CircuitBreakerInterval: 60 * time.Second,
				CircuitBreakerTimeout: 30 * time.Second,
				MaxTokenLength:   8192,
				ValidateURL:      true,
				LogLevel:         "info",
				LogFormat:        "json",
			},
			wantError: true,
		},
		{
			name: "Timeout too large",
			config: &Config{
				AuthServiceURL:   "http://localhost:8080",
				ValidateEndpoint: "/validate",
				TokenHeader:      "Authorization",
				Timeout:          10 * time.Minute,
				RetryWaitMin:     100 * time.Millisecond,
				RetryWaitMax:     2 * time.Second,
				CircuitBreakerInterval: 60 * time.Second,
				CircuitBreakerTimeout: 30 * time.Second,
				MaxTokenLength:   8192,
				LogLevel:         "info",
				LogFormat:        "json",
			},
			wantError: true,
		},
		{
			name: "Negative retries",
			config: &Config{
				AuthServiceURL:   "http://localhost:8080",
				ValidateEndpoint: "/validate",
				TokenHeader:      "Authorization",
				Timeout:          10 * time.Second,
				MaxRetries:       -1,
				RetryWaitMin:     100 * time.Millisecond,
				RetryWaitMax:     2 * time.Second,
				CircuitBreakerInterval: 60 * time.Second,
				CircuitBreakerTimeout: 30 * time.Second,
				MaxTokenLength:   8192,
				LogLevel:         "info",
				LogFormat:        "json",
			},
			wantError: true,
		},
		{
			name: "Invalid log level",
			config: &Config{
				AuthServiceURL:   "http://localhost:8080",
				ValidateEndpoint: "/validate",
				TokenHeader:      "Authorization",
				Timeout:          10 * time.Second,
				MaxRetries:       3,
				RetryWaitMin:     100 * time.Millisecond,
				RetryWaitMax:     2 * time.Second,
				CircuitBreakerInterval: 60 * time.Second,
				CircuitBreakerTimeout: 30 * time.Second,
				MaxTokenLength:   8192,
				LogLevel:         "invalid",
				LogFormat:        "json",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Validate() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidationError(t *testing.T) {
	cfg := &Config{
		AuthServiceURL: "",
		Timeout:        -1 * time.Second,
		MaxRetries:     -1,
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Expected validation error")
	}

	validationErr, ok := err.(*ValidationError)
	if !ok {
		t.Fatal("Expected ValidationError type")
	}

	if len(validationErr.Errors) < 2 {
		t.Errorf("Expected multiple errors, got %d", len(validationErr.Errors))
	}
}

func cleanupEnv() {
	os.Unsetenv("AUTH_SERVICE_URL")
	os.Unsetenv("AUTH_VALIDATE_ENDPOINT")
	os.Unsetenv("AUTH_TOKEN_HEADER")
	os.Unsetenv("AUTH_TOKEN_PREFIX")
	os.Unsetenv("AUTH_TIMEOUT")
	os.Unsetenv("AUTH_MAX_RETRIES")
}
