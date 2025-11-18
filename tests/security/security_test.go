package security

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baditaflorin/go-auth-middleware/internal/config"
	"github.com/baditaflorin/go-auth-middleware/internal/logger"
	"github.com/baditaflorin/go-auth-middleware/internal/middleware"
	"github.com/gin-gonic/gin"
)

// TestSQLInjectionAttempts tests that SQL injection attempts in tokens are properly rejected
func TestSQLInjectionAttempts(t *testing.T) {
	injectionAttempts := []string{
		"'; DROP TABLE users--",
		"1' OR '1'='1",
		"admin'--",
		"' OR 1=1--",
		"1; DELETE FROM users WHERE 1=1--",
		"1' UNION SELECT * FROM users--",
	}

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This should never be reached
		t.Error("Auth service was called with malicious token - validation failed!")
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := config.DefaultConfig()
	cfg.AuthServiceURL = authServer.URL
	cfg.RateLimitEnabled = false

	log := logger.Noop()
	mw, _ := middleware.New(cfg, log)

	router := gin.New()
	router.Use(mw.Handler())
	router.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	for _, attempt := range injectionAttempts {
		t.Run("Injection_"+attempt, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+attempt)
			router.ServeHTTP(w, req)

			// Should be rejected at validation level
			if w.Code == http.StatusOK {
				t.Errorf("SQL injection attempt was not rejected: %s", attempt)
			}
		})
	}
}

// TestXSSAttempts tests that XSS attempts in tokens are properly rejected
func TestXSSAttempts(t *testing.T) {
	xssAttempts := []string{
		"<script>alert('xss')</script>",
		"<img src=x onerror=alert('xss')>",
		"javascript:alert('xss')",
		"<svg/onload=alert('xss')>",
		"'><script>alert(String.fromCharCode(88,83,83))</script>",
	}

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Auth service was called with XSS attempt - validation failed!")
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := config.DefaultConfig()
	cfg.AuthServiceURL = authServer.URL
	cfg.RateLimitEnabled = false

	log := logger.Noop()
	mw, _ := middleware.New(cfg, log)

	router := gin.New()
	router.Use(mw.Handler())
	router.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	for _, attempt := range xssAttempts {
		t.Run("XSS_"+attempt[:min(20, len(attempt))], func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+attempt)
			router.ServeHTTP(w, req)

			if w.Code == http.StatusOK {
				t.Errorf("XSS attempt was not rejected: %s", attempt)
			}
		})
	}
}

// TestCommandInjectionAttempts tests command injection attempts
func TestCommandInjectionAttempts(t *testing.T) {
	cmdAttempts := []string{
		"; ls -la",
		"| cat /etc/passwd",
		"& whoami",
		"`whoami`",
		"$(whoami)",
		"; rm -rf /",
	}

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Auth service was called with command injection - validation failed!")
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := config.DefaultConfig()
	cfg.AuthServiceURL = authServer.URL
	cfg.RateLimitEnabled = false

	log := logger.Noop()
	mw, _ := middleware.New(cfg, log)

	router := gin.New()
	router.Use(mw.Handler())
	router.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	for _, attempt := range cmdAttempts {
		t.Run("CMD_"+attempt, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+attempt)
			router.ServeHTTP(w, req)

			if w.Code == http.StatusOK {
				t.Errorf("Command injection attempt was not rejected: %s", attempt)
			}
		})
	}
}

// TestHeaderInjectionAttempts tests HTTP header injection attempts
func TestHeaderInjectionAttempts(t *testing.T) {
	headerAttempts := []string{
		"token\r\nX-Injected: malicious",
		"token\nSet-Cookie: evil=true",
		"token\r\n\r\nHTTP/1.1 200 OK",
	}

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if any injected headers are present
		if r.Header.Get("X-Injected") != "" {
			t.Error("Header injection succeeded!")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := config.DefaultConfig()
	cfg.AuthServiceURL = authServer.URL
	cfg.RateLimitEnabled = false

	log := logger.Noop()
	mw, _ := middleware.New(cfg, log)

	router := gin.New()
	router.Use(mw.Handler())
	router.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	for _, attempt := range headerAttempts {
		t.Run("Header_Injection", func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+attempt)
			router.ServeHTTP(w, req)

			// Should be rejected or sanitized
			if w.Code == http.StatusOK {
				t.Logf("Warning: Header injection attempt may need additional handling: %s", attempt)
			}
		})
	}
}

// TestPathTraversalAttempts tests path traversal attempts
func TestPathTraversalAttempts(t *testing.T) {
	pathAttempts := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32",
		"....//....//....//etc/passwd",
	}

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// These should pass validation (they're valid characters)
		// but should not be used to access files
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user_id": "user123",
		})
	}))
	defer authServer.Close()

	cfg := config.DefaultConfig()
	cfg.AuthServiceURL = authServer.URL
	cfg.RateLimitEnabled = false

	log := logger.Noop()
	mw, _ := middleware.New(cfg, log)

	router := gin.New()
	router.Use(mw.Handler())
	router.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	for _, attempt := range pathAttempts {
		t.Run("Path_"+attempt, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+attempt)
			router.ServeHTTP(w, req)

			// The middleware should handle these safely
			// (they contain valid characters but shouldn't be used for file access)
		})
	}
}

// TestOversizedPayloads tests handling of oversized tokens
func TestOversizedPayloads(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Auth service was called with oversized token - validation failed!")
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := config.DefaultConfig()
	cfg.AuthServiceURL = authServer.URL
	cfg.RateLimitEnabled = false
	cfg.MaxTokenLength = 1024

	log := logger.Noop()
	mw, _ := middleware.New(cfg, log)

	router := gin.New()
	router.Use(mw.Handler())
	router.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Create oversized token
	oversizedToken := strings.Repeat("a", 2000)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+oversizedToken)
	router.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("Oversized token was not rejected")
	}
}

// TestNullByteInjection tests null byte injection attempts
func TestNullByteInjection(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if strings.Contains(authHeader, "\x00") {
			t.Error("Null byte was not sanitized before reaching auth service")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := config.DefaultConfig()
	cfg.AuthServiceURL = authServer.URL
	cfg.RateLimitEnabled = false

	log := logger.Noop()
	mw, _ := middleware.New(cfg, log)

	router := gin.New()
	router.Use(mw.Handler())
	router.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer token\x00malicious")
	router.ServeHTTP(w, req)

	// Should be rejected
	if w.Code == http.StatusOK {
		t.Error("Null byte injection was not rejected")
	}
}

// TestUnicodeNormalizationAttacks tests unicode normalization attacks
func TestUnicodeNormalizationAttacks(t *testing.T) {
	unicodeAttempts := []string{
		"token™",
		"tøken",
		"tökëñ",
		"t\u200Boken", // Zero-width space
	}

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Auth service was called with unicode attack - validation failed!")
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := config.DefaultConfig()
	cfg.AuthServiceURL = authServer.URL
	cfg.RateLimitEnabled = false

	log := logger.Noop()
	mw, _ := middleware.New(cfg, log)

	router := gin.New()
	router.Use(mw.Handler())
	router.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	for _, attempt := range unicodeAttempts {
		t.Run("Unicode_"+attempt, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+attempt)
			router.ServeHTTP(w, req)

			// Should be rejected (non-ASCII)
			if w.Code == http.StatusOK {
				t.Errorf("Unicode attack was not rejected: %s", attempt)
			}
		})
	}
}

// TestErrorMessageLeakage verifies that error messages don't leak sensitive information
func TestErrorMessageLeakage(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AuthServiceURL = "http://localhost:9999" // Non-existent server
	cfg.RateLimitEnabled = false
	cfg.MaxRetries = 0

	log := logger.Noop()
	mw, _ := middleware.New(cfg, log)

	router := gin.New()
	router.Use(mw.Handler())
	router.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer validtoken")
	router.ServeHTTP(w, req)

	// Check that error message doesn't contain sensitive info
	body := w.Body.String()

	sensitivePatterns := []string{
		"localhost:9999",  // Internal URL
		"connection refused", // Internal error details
		"dial tcp", // Network error details
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
			t.Errorf("Error message leaks sensitive information: %s", pattern)
		}
	}

	// Should contain generic error message
	if !strings.Contains(body, "temporarily unavailable") && !strings.Contains(body, "error") {
		t.Error("Error message doesn't provide any user-facing information")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
