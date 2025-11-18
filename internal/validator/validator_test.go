package validator

import (
	"strings"
	"testing"
)

func TestTokenValidator_ValidateToken(t *testing.T) {
	validator := NewTokenValidator(1024)

	tests := []struct {
		name      string
		token     string
		wantError bool
	}{
		{
			name:      "Valid JWT token",
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			wantError: false,
		},
		{
			name:      "Valid simple token",
			token:     "abc123-xyz_789",
			wantError: false,
		},
		{
			name:      "Empty token",
			token:     "",
			wantError: true,
		},
		{
			name:      "Token with spaces (invalid)",
			token:     "token with spaces",
			wantError: true,
		},
		{
			name:      "Token with SQL injection attempt",
			token:     "abc'; DROP TABLE users--",
			wantError: true,
		},
		{
			name:      "Token with XSS attempt",
			token:     "<script>alert('xss')</script>",
			wantError: true,
		},
		{
			name:      "Token with null bytes",
			token:     "abc\x00def",
			wantError: true,
		},
		{
			name:      "Token with newlines",
			token:     "abc\ndef",
			wantError: true,
		},
		{
			name:      "Token with control characters",
			token:     "abc\x01\x02def",
			wantError: true,
		},
		{
			name:      "Token too long",
			token:     strings.Repeat("a", 2000),
			wantError: true,
		},
		{
			name:      "Token with unicode",
			token:     "token™",
			wantError: true,
		},
		{
			name:      "Token with path traversal attempt",
			token:     "../../../etc/passwd",
			wantError: false, // Valid characters, just a string
		},
		{
			name:      "Token with command injection attempt",
			token:     "abc; rm -rf /",
			wantError: true, // Contains semicolon and spaces
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateToken(tt.token)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateToken() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		prefix      string
		want        string
		wantError   bool
	}{
		{
			name:        "Valid Bearer token",
			headerValue: "Bearer abc123",
			prefix:      "Bearer ",
			want:        "abc123",
			wantError:   false,
		},
		{
			name:        "Valid token without prefix",
			headerValue: "abc123",
			prefix:      "",
			want:        "abc123",
			wantError:   false,
		},
		{
			name:        "Token with extra spaces",
			headerValue: "Bearer   abc123  ",
			prefix:      "Bearer ",
			want:        "abc123",
			wantError:   false,
		},
		{
			name:        "Empty header",
			headerValue: "",
			prefix:      "Bearer ",
			want:        "",
			wantError:   true,
		},
		{
			name:        "Missing prefix",
			headerValue: "abc123",
			prefix:      "Bearer ",
			want:        "",
			wantError:   true,
		},
		{
			name:        "Wrong prefix",
			headerValue: "Token abc123",
			prefix:      "Bearer ",
			want:        "",
			wantError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractToken(tt.headerValue, tt.prefix)
			if (err != nil) != tt.wantError {
				t.Errorf("ExtractToken() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if got != tt.want {
				t.Errorf("ExtractToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeHeaderName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      string
		wantError bool
	}{
		{
			name:      "Valid header",
			input:     "Authorization",
			want:      "Authorization",
			wantError: false,
		},
		{
			name:      "Valid header with hyphen",
			input:     "X-Auth-Token",
			want:      "X-Auth-Token",
			wantError: false,
		},
		{
			name:      "Empty header",
			input:     "",
			want:      "",
			wantError: true,
		},
		{
			name:      "Header with spaces",
			input:     "Auth Token",
			want:      "",
			wantError: true,
		},
		{
			name:      "Header with special chars",
			input:     "Auth@Token",
			want:      "",
			wantError: true,
		},
		{
			name:      "Header with injection attempt",
			input:     "Auth\r\nInjected: value",
			want:      "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizeHeaderName(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("SanitizeHeaderName() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if got != tt.want {
				t.Errorf("SanitizeHeaderName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Clean string",
			input: "Hello World",
			want:  "Hello World",
		},
		{
			name:  "String with null byte",
			input: "Hello\x00World",
			want:  "HelloWorld",
		},
		{
			name:  "String with control characters",
			input: "Hello\x01\x02World",
			want:  "HelloWorld",
		},
		{
			name:  "String with newline (allowed)",
			input: "Hello\nWorld",
			want:  "Hello\nWorld",
		},
		{
			name:  "String with tab (allowed)",
			input: "Hello\tWorld",
			want:  "Hello\tWorld",
		},
		{
			name:  "String with multiple issues",
			input: "Hello\x00\x01\x02World\x03",
			want:  "HelloWorld",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeString(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateResponseField(t *testing.T) {
	tests := []struct {
		name      string
		field     interface{}
		want      string
		wantError bool
	}{
		{
			name:      "Valid string",
			field:     "user123",
			want:      "user123",
			wantError: false,
		},
		{
			name:      "Empty string",
			field:     "",
			want:      "",
			wantError: true,
		},
		{
			name:      "Non-string field",
			field:     123,
			want:      "",
			wantError: true,
		},
		{
			name:      "String with control chars",
			field:     "user\x00123",
			want:      "user123",
			wantError: false,
		},
		{
			name:      "Nil field",
			field:     nil,
			want:      "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateResponseField(tt.field)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateResponseField() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateResponseField() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Benchmark tests for performance
func BenchmarkValidateToken(b *testing.B) {
	validator := NewTokenValidator(8192)
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateToken(token)
	}
}

func BenchmarkSanitizeString(b *testing.B) {
	input := "Hello\x00World\x01Test\x02String"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SanitizeString(input)
	}
}
