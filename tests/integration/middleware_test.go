package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/baditaflorin/go-auth-middleware/internal/config"
	"github.com/baditaflorin/go-auth-middleware/internal/logger"
	"github.com/baditaflorin/go-auth-middleware/internal/middleware"
	"github.com/gin-gonic/gin"
)

func TestMiddleware_Success(t *testing.T) {
	// Create mock auth service
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for auth header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || authHeader != "Bearer validtoken" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Return success
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user_id": "user123",
			"email":   "user@example.com",
		})
	}))
	defer authServer.Close()

	// Create config
	cfg := config.DefaultConfig()
	cfg.AuthServiceURL = authServer.URL
	cfg.RateLimitEnabled = false

	// Create middleware
	log := logger.Noop()
	mw, err := middleware.New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create middleware: %v", err)
	}

	// Create test router
	router := gin.New()
	router.Use(mw.Handler())
	router.GET("/protected", func(c *gin.Context) {
		userID := c.GetString("user_id")
		c.JSON(http.StatusOK, gin.H{"user_id": userID})
	})

	// Make request with valid token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer validtoken")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	if response["user_id"] != "user123" {
		t.Errorf("Expected user_id 'user123', got '%s'", response["user_id"])
	}
}

func TestMiddleware_MissingToken(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestMiddleware_InvalidToken(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
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
	req.Header.Set("Authorization", "Bearer invalidtoken")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestMiddleware_RateLimit(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user_id": "user123",
		})
	}))
	defer authServer.Close()

	cfg := config.DefaultConfig()
	cfg.AuthServiceURL = authServer.URL
	cfg.RateLimitEnabled = true
	cfg.RateLimitRPS = 2 // Very low limit for testing

	log := logger.Noop()
	mw, _ := middleware.New(cfg, log)

	router := gin.New()
	router.Use(mw.Handler())
	router.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// First two requests should succeed
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer validtoken")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}

	// Third request should be rate limited
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer validtoken")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429 (rate limited), got %d", w.Code)
	}
}

func TestMiddleware_AuthServiceDown(t *testing.T) {
	// Create config pointing to non-existent server
	cfg := config.DefaultConfig()
	cfg.AuthServiceURL = "http://localhost:9999"
	cfg.RateLimitEnabled = false
	cfg.MaxRetries = 0 // No retries for faster test
	cfg.Timeout = 1 * time.Second

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

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", w.Code)
	}
}

func TestMiddleware_MalformedResponse(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
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
	req.Header.Set("Authorization", "Bearer validtoken")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestMiddleware_HealthCheck(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer authServer.Close()

	cfg := config.DefaultConfig()
	cfg.AuthServiceURL = authServer.URL
	cfg.RateLimitEnabled = false

	log := logger.Noop()
	mw, _ := middleware.New(cfg, log)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := mw.HealthCheck(ctx)
	if err != nil {
		t.Errorf("Health check failed: %v", err)
	}
}

func TestMiddleware_Metrics(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	// Reset metrics
	mw.ResetMetrics()

	router := gin.New()
	router.Use(mw.Handler())
	router.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Make successful request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer validtoken")
	router.ServeHTTP(w, req)

	// Check metrics
	metrics := mw.GetMetrics()
	if metrics.TotalRequests != 1 {
		t.Errorf("Expected 1 total request, got %d", metrics.TotalRequests)
	}
	if metrics.SuccessfulAuths != 1 {
		t.Errorf("Expected 1 successful auth, got %d", metrics.SuccessfulAuths)
	}

	// Make failed request
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/protected", nil)
	router.ServeHTTP(w, req)

	// Check updated metrics
	metrics = mw.GetMetrics()
	if metrics.TotalRequests != 2 {
		t.Errorf("Expected 2 total requests, got %d", metrics.TotalRequests)
	}
	if metrics.FailedAuths != 1 {
		t.Errorf("Expected 1 failed auth, got %d", metrics.FailedAuths)
	}
}

// Benchmark tests
func BenchmarkMiddleware_SuccessPath(b *testing.B) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer validtoken")
		router.ServeHTTP(w, req)
	}
}
