package errors

import (
	"errors"
	"fmt"
)

// ErrorCode represents a type of error
type ErrorCode string

const (
	// ErrCodeInvalidToken indicates the token is missing or malformed
	ErrCodeInvalidToken ErrorCode = "INVALID_TOKEN"

	// ErrCodeUnauthorized indicates the token was rejected by the auth service
	ErrCodeUnauthorized ErrorCode = "UNAUTHORIZED"

	// ErrCodeAuthServiceUnavailable indicates the auth service is unreachable
	ErrCodeAuthServiceUnavailable ErrorCode = "AUTH_SERVICE_UNAVAILABLE"

	// ErrCodeRateLimitExceeded indicates too many requests
	ErrCodeRateLimitExceeded ErrorCode = "RATE_LIMIT_EXCEEDED"

	// ErrCodeCircuitOpen indicates the circuit breaker is open
	ErrCodeCircuitOpen ErrorCode = "CIRCUIT_OPEN"

	// ErrCodeInternal indicates an internal error occurred
	ErrCodeInternal ErrorCode = "INTERNAL_ERROR"

	// ErrCodeInvalidConfig indicates a configuration error
	ErrCodeInvalidConfig ErrorCode = "INVALID_CONFIG"

	// ErrCodeValidationFailed indicates input validation failed
	ErrCodeValidationFailed ErrorCode = "VALIDATION_FAILED"
)

// AuthError represents an authentication middleware error
type AuthError struct {
	Code       ErrorCode
	Message    string // Safe, user-facing message
	Internal   error  // Internal error (never exposed to users)
	StatusCode int    // HTTP status code to return
}

func (e *AuthError) Error() string {
	if e.Internal != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Internal)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *AuthError) Unwrap() error {
	return e.Internal
}

// UserMessage returns a sanitized message safe for user display
func (e *AuthError) UserMessage() string {
	return e.Message
}

// NewInvalidTokenError creates an error for invalid/missing tokens
func NewInvalidTokenError(internal error) *AuthError {
	return &AuthError{
		Code:       ErrCodeInvalidToken,
		Message:    "Invalid or missing authentication token",
		Internal:   internal,
		StatusCode: 401,
	}
}

// NewUnauthorizedError creates an error for rejected tokens
func NewUnauthorizedError(internal error) *AuthError {
	return &AuthError{
		Code:       ErrCodeUnauthorized,
		Message:    "Authentication failed",
		Internal:   internal,
		StatusCode: 401,
	}
}

// NewAuthServiceUnavailableError creates an error for auth service failures
func NewAuthServiceUnavailableError(internal error) *AuthError {
	return &AuthError{
		Code:       ErrCodeAuthServiceUnavailable,
		Message:    "Authentication service temporarily unavailable",
		Internal:   internal,
		StatusCode: 503,
	}
}

// NewRateLimitError creates an error for rate limit violations
func NewRateLimitError() *AuthError {
	return &AuthError{
		Code:       ErrCodeRateLimitExceeded,
		Message:    "Rate limit exceeded, please try again later",
		Internal:   nil,
		StatusCode: 429,
	}
}

// NewCircuitOpenError creates an error for circuit breaker open state
func NewCircuitOpenError() *AuthError {
	return &AuthError{
		Code:       ErrCodeCircuitOpen,
		Message:    "Authentication service temporarily unavailable",
		Internal:   errors.New("circuit breaker open"),
		StatusCode: 503,
	}
}

// NewInternalError creates an error for unexpected internal failures
func NewInternalError(internal error) *AuthError {
	return &AuthError{
		Code:       ErrCodeInternal,
		Message:    "An internal error occurred",
		Internal:   internal,
		StatusCode: 500,
	}
}

// NewValidationError creates an error for validation failures
func NewValidationError(message string, internal error) *AuthError {
	return &AuthError{
		Code:       ErrCodeValidationFailed,
		Message:    message,
		Internal:   internal,
		StatusCode: 400,
	}
}

// NewConfigError creates an error for configuration problems
func NewConfigError(internal error) *AuthError {
	return &AuthError{
		Code:       ErrCodeInvalidConfig,
		Message:    "Configuration error",
		Internal:   internal,
		StatusCode: 500,
	}
}
