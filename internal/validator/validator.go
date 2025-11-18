package validator

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	// ErrTokenTooLong indicates the token exceeds maximum length
	ErrTokenTooLong = errors.New("token exceeds maximum allowed length")

	// ErrTokenEmpty indicates the token is empty
	ErrTokenEmpty = errors.New("token is empty")

	// ErrTokenInvalidChars indicates the token contains invalid characters
	ErrTokenInvalidChars = errors.New("token contains invalid characters")

	// ErrHeaderNameInvalid indicates the header name is invalid
	ErrHeaderNameInvalid = errors.New("header name is invalid")
)

// TokenValidator validates authentication tokens
type TokenValidator struct {
	maxLength int
	// Allow alphanumeric, dots, dashes, underscores, and common JWT characters
	validCharsPattern *regexp.Regexp
}

// NewTokenValidator creates a new token validator
func NewTokenValidator(maxLength int) *TokenValidator {
	return &TokenValidator{
		maxLength:         maxLength,
		validCharsPattern: regexp.MustCompile(`^[A-Za-z0-9\-_.~+/=]+$`),
	}
}

// ValidateToken validates a token string
func (v *TokenValidator) ValidateToken(token string) error {
	// Check if empty
	if token == "" {
		return ErrTokenEmpty
	}

	// Check length
	if len(token) > v.maxLength {
		return fmt.Errorf("%w: got %d, max %d", ErrTokenTooLong, len(token), v.maxLength)
	}

	// Check for valid UTF-8
	if !utf8.ValidString(token) {
		return ErrTokenInvalidChars
	}

	// Check character whitelist
	if !v.validCharsPattern.MatchString(token) {
		return ErrTokenInvalidChars
	}

	return nil
}

// ExtractToken extracts the token from a header value, removing the prefix
func ExtractToken(headerValue, prefix string) (string, error) {
	if headerValue == "" {
		return "", ErrTokenEmpty
	}

	// Remove prefix if present
	if prefix != "" {
		if !strings.HasPrefix(headerValue, prefix) {
			return "", fmt.Errorf("token does not start with expected prefix: %s", prefix)
		}
		token := strings.TrimPrefix(headerValue, prefix)
		return strings.TrimSpace(token), nil
	}

	return strings.TrimSpace(headerValue), nil
}

// SanitizeHeaderName sanitizes HTTP header names
func SanitizeHeaderName(name string) (string, error) {
	if name == "" {
		return "", ErrHeaderNameInvalid
	}

	// HTTP header names should be ASCII alphanumeric plus hyphen
	validHeaderPattern := regexp.MustCompile(`^[A-Za-z0-9\-]+$`)
	if !validHeaderPattern.MatchString(name) {
		return "", fmt.Errorf("%w: %s", ErrHeaderNameInvalid, name)
	}

	return name, nil
}

// SanitizeString performs basic sanitization on string inputs
// It removes null bytes and control characters
func SanitizeString(s string) string {
	// Remove null bytes
	s = strings.ReplaceAll(s, "\x00", "")

	// Remove other control characters except newline and tab
	var builder strings.Builder
	for _, r := range s {
		if r >= 32 || r == '\n' || r == '\t' {
			builder.WriteRune(r)
		}
	}

	return builder.String()
}

// ValidateResponseField validates a field from the auth service response
func ValidateResponseField(field interface{}) (string, error) {
	str, ok := field.(string)
	if !ok {
		return "", errors.New("field is not a string")
	}

	if str == "" {
		return "", errors.New("field is empty")
	}

	// Sanitize control characters
	str = SanitizeString(str)

	return str, nil
}
