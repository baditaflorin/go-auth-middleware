package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/baditaflorin/go-auth-middleware/internal/config"
	"github.com/baditaflorin/go-auth-middleware/internal/logger"
	"github.com/baditaflorin/go-auth-middleware/internal/middleware"
	"github.com/gin-gonic/gin"
)

var (
	currentConfig *config.Config
	currentMiddleware *middleware.AuthMiddleware
	appLogger *logger.Logger
)

func main() {
	// Initialize logger
	appLogger = logger.New("info", "text", os.Stdout)

	// Load initial config from env or use defaults
	cfg, err := config.LoadFromEnv()
	if err != nil {
		appLogger.Warn("Failed to load config from env, using defaults", map[string]interface{}{
			"error": err.Error(),
		})
		cfg = config.DefaultConfig()
		// Set a placeholder URL for GUI mode
		cfg.AuthServiceURL = "http://localhost:8080"
	}
	currentConfig = cfg

	// Start web server
	port := os.Getenv("GUI_PORT")
	if port == "" {
		port = "3000"
	}

	router := gin.Default()
	setupRoutes(router)

	appLogger.Info("Starting GUI server", map[string]interface{}{
		"port": port,
	})

	fmt.Printf("\n===========================================\n")
	fmt.Printf("Auth Middleware Test Harness\n")
	fmt.Printf("===========================================\n")
	fmt.Printf("Server running at: http://localhost:%s\n", port)
	fmt.Printf("===========================================\n\n")

	if err := router.Run(":" + port); err != nil {
		log.Fatal(err)
	}
}

func setupRoutes(router *gin.Engine) {
	// Serve the main GUI page
	router.GET("/", handleIndex)

	// API endpoints
	api := router.Group("/api")
	{
		api.GET("/config", handleGetConfig)
		api.POST("/config", handleSaveConfig)
		api.POST("/config/validate", handleValidateConfig)
		api.POST("/test/validate", handleTestValidate)
		api.GET("/metrics", handleGetMetrics)
		api.POST("/metrics/reset", handleResetMetrics)
		api.GET("/health", handleHealth)
		api.GET("/circuit-breaker", handleCircuitBreakerState)
	}
}

func handleIndex(c *gin.Context) {
	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, guiHTML)
}

func handleGetConfig(c *gin.Context) {
	c.JSON(http.StatusOK, currentConfig)
}

func handleSaveConfig(c *gin.Context) {
	var cfg config.Config
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate the new config
	if err := cfg.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update current config
	currentConfig = &cfg

	// Recreate middleware with new config
	mw, err := middleware.New(currentConfig, appLogger)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	currentMiddleware = mw

	c.JSON(http.StatusOK, gin.H{
		"message": "Configuration saved successfully",
		"config":  currentConfig,
	})
}

func handleValidateConfig(c *gin.Context) {
	var cfg config.Config
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	if err := cfg.Validate(); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":   true,
		"message": "Configuration is valid",
	})
}

func handleTestValidate(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Ensure middleware is initialized
	if currentMiddleware == nil {
		mw, err := middleware.New(currentConfig, appLogger)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		currentMiddleware = mw
	}

	// Create a mock Gin context for testing
	mockWriter := &mockResponseWriter{header: make(http.Header)}
	mockContext, _ := gin.CreateTestContext(mockWriter)
	mockContext.Request = &http.Request{
		Header: make(http.Header),
	}
	mockContext.Request.Header.Set(currentConfig.TokenHeader, currentConfig.TokenPrefix+req.Token)

	// Run the middleware
	startTime := time.Now()
	currentMiddleware.Handler()(mockContext)
	duration := time.Since(startTime)

	// Check result
	if mockWriter.statusCode == 0 {
		// Success - middleware didn't abort
		c.JSON(http.StatusOK, gin.H{
			"valid":        true,
			"status_code":  200,
			"duration_ms":  duration.Milliseconds(),
			"user_id":      mockContext.GetString(currentConfig.UserIDKey),
			"message":      "Token validated successfully",
		})
	} else {
		// Failed - extract error from response
		var errorResponse map[string]interface{}
		if mockWriter.body != nil {
			json.Unmarshal(mockWriter.body, &errorResponse)
		}

		c.JSON(http.StatusOK, gin.H{
			"valid":       false,
			"status_code": mockWriter.statusCode,
			"duration_ms": duration.Milliseconds(),
			"error":       errorResponse,
		})
	}
}

func handleGetMetrics(c *gin.Context) {
	if currentMiddleware == nil {
		c.JSON(http.StatusOK, gin.H{
			"total_requests":       0,
			"successful_auths":     0,
			"failed_auths":         0,
			"rate_limit_hits":      0,
			"circuit_breaker_hits": 0,
			"average_latency_ms":   0,
		})
		return
	}

	metrics := currentMiddleware.GetMetrics()
	c.JSON(http.StatusOK, metrics)
}

func handleResetMetrics(c *gin.Context) {
	if currentMiddleware != nil {
		currentMiddleware.ResetMetrics()
	}
	c.JSON(http.StatusOK, gin.H{"message": "Metrics reset successfully"})
}

func handleHealth(c *gin.Context) {
	if currentMiddleware == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"healthy": false,
			"error":   "Middleware not initialized",
		})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := currentMiddleware.HealthCheck(ctx)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"healthy": false,
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"healthy": true,
		"message": "Auth service is healthy",
	})
}

func handleCircuitBreakerState(c *gin.Context) {
	if currentMiddleware == nil {
		c.JSON(http.StatusOK, gin.H{
			"state": "unknown",
		})
		return
	}

	state := currentMiddleware.GetCircuitBreakerState()
	c.JSON(http.StatusOK, gin.H{
		"state": state,
	})
}

// mockResponseWriter is a mock HTTP response writer for testing
type mockResponseWriter struct {
	header     http.Header
	body       []byte
	statusCode int
}

func (m *mockResponseWriter) Header() http.Header {
	return m.header
}

func (m *mockResponseWriter) Write(b []byte) (int, error) {
	m.body = append(m.body, b...)
	return len(b), nil
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {
	m.statusCode = statusCode
}

const guiHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auth Middleware Test Harness</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        h1 {
            color: #333;
            margin-bottom: 30px;
            text-align: center;
        }
        .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .card h2 {
            color: #333;
            margin-bottom: 15px;
            font-size: 18px;
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: 500;
            font-size: 14px;
        }
        input[type="text"], input[type="number"], select, textarea {
            width: 100%;
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        textarea {
            min-height: 80px;
            font-family: monospace;
        }
        button {
            background: #007bff;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
        }
        button:hover {
            background: #0056b3;
        }
        button.secondary {
            background: #6c757d;
        }
        button.secondary:hover {
            background: #545b62;
        }
        button.success {
            background: #28a745;
        }
        button.success:hover {
            background: #218838;
        }
        .response {
            background: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            margin-top: 15px;
            font-family: monospace;
            font-size: 13px;
            max-height: 400px;
            overflow-y: auto;
        }
        .response pre {
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
        }
        .metric {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            text-align: center;
        }
        .metric-value {
            font-size: 28px;
            font-weight: bold;
            color: #007bff;
        }
        .metric-label {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }
        .status-success {
            background: #d4edda;
            color: #155724;
        }
        .status-error {
            background: #f8d7da;
            color: #721c24;
        }
        .status-warning {
            background: #fff3cd;
            color: #856404;
        }
        .button-group {
            display: flex;
            gap: 10px;
            margin-top: 15px;
        }
        .full-width {
            grid-column: 1 / -1;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Auth Middleware Test Harness</h1>

        <div class="grid">
            <!-- Configuration -->
            <div class="card">
                <h2>Configuration</h2>
                <div class="form-group">
                    <label>Auth Service URL</label>
                    <input type="text" id="authServiceURL" value="http://localhost:8080">
                </div>
                <div class="form-group">
                    <label>Validate Endpoint</label>
                    <input type="text" id="validateEndpoint" value="/validate">
                </div>
                <div class="form-group">
                    <label>Token Header</label>
                    <input type="text" id="tokenHeader" value="Authorization">
                </div>
                <div class="form-group">
                    <label>Token Prefix</label>
                    <input type="text" id="tokenPrefix" value="Bearer ">
                </div>
                <div class="form-group">
                    <label>Request Timeout (e.g., 10s)</label>
                    <input type="text" id="timeout" value="10s">
                </div>
                <div class="form-group">
                    <label>Max Retries</label>
                    <input type="number" id="maxRetries" value="3" min="0" max="10">
                </div>
                <div class="form-group">
                    <label>Rate Limit (RPS)</label>
                    <input type="number" id="rateLimitRPS" value="100" min="1" max="10000">
                </div>
                <div class="button-group">
                    <button onclick="validateConfig()">Validate</button>
                    <button class="success" onclick="saveConfig()">Save Config</button>
                    <button class="secondary" onclick="loadConfig()">Load</button>
                </div>
                <div id="configResponse" class="response" style="display:none;"></div>
            </div>

            <!-- Test Token Validation -->
            <div class="card">
                <h2>Test Token Validation</h2>
                <div class="form-group">
                    <label>Test Token</label>
                    <textarea id="testToken" placeholder="Enter your test token here...">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test</textarea>
                </div>
                <div class="button-group">
                    <button class="success" onclick="testValidation()">Validate Token</button>
                </div>
                <div id="testResponse" class="response" style="display:none;"></div>
            </div>

            <!-- Metrics -->
            <div class="card full-width">
                <h2>Metrics & Monitoring</h2>
                <div class="metrics-grid">
                    <div class="metric">
                        <div class="metric-value" id="totalRequests">0</div>
                        <div class="metric-label">Total Requests</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" id="successfulAuths">0</div>
                        <div class="metric-label">Successful</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" id="failedAuths">0</div>
                        <div class="metric-label">Failed</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" id="rateLimitHits">0</div>
                        <div class="metric-label">Rate Limited</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" id="circuitBreakerHits">0</div>
                        <div class="metric-label">Circuit Breaker</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" id="avgLatency">0</div>
                        <div class="metric-label">Avg Latency (ms)</div>
                    </div>
                </div>
                <div class="button-group">
                    <button onclick="refreshMetrics()">Refresh</button>
                    <button class="secondary" onclick="resetMetrics()">Reset Metrics</button>
                    <button class="secondary" onclick="checkHealth()">Health Check</button>
                    <button class="secondary" onclick="checkCircuitBreaker()">Circuit Breaker State</button>
                </div>
                <div id="healthResponse" class="response" style="display:none;"></div>
            </div>
        </div>
    </div>

    <script>
        // Load config on startup
        loadConfig();
        refreshMetrics();

        async function loadConfig() {
            try {
                const response = await fetch('/api/config');
                const config = await response.json();

                document.getElementById('authServiceURL').value = config.auth_service_url || '';
                document.getElementById('validateEndpoint').value = config.validate_endpoint || '/validate';
                document.getElementById('tokenHeader').value = config.token_header || 'Authorization';
                document.getElementById('tokenPrefix').value = config.token_prefix || 'Bearer ';
                document.getElementById('timeout').value = config.timeout || '10s';
                document.getElementById('maxRetries').value = config.max_retries || 3;
                document.getElementById('rateLimitRPS').value = config.rate_limit_rps || 100;
            } catch (error) {
                showResponse('configResponse', 'Error loading config: ' + error.message, false);
            }
        }

        async function validateConfig() {
            const config = buildConfig();
            try {
                const response = await fetch('/api/config/validate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(config)
                });
                const result = await response.json();
                showResponse('configResponse', JSON.stringify(result, null, 2), result.valid);
            } catch (error) {
                showResponse('configResponse', 'Error: ' + error.message, false);
            }
        }

        async function saveConfig() {
            const config = buildConfig();
            try {
                const response = await fetch('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(config)
                });
                const result = await response.json();
                showResponse('configResponse', JSON.stringify(result, null, 2), response.ok);
            } catch (error) {
                showResponse('configResponse', 'Error: ' + error.message, false);
            }
        }

        async function testValidation() {
            const token = document.getElementById('testToken').value.trim();
            if (!token) {
                showResponse('testResponse', 'Please enter a token', false);
                return;
            }

            try {
                const response = await fetch('/api/test/validate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token })
                });
                const result = await response.json();
                showResponse('testResponse', JSON.stringify(result, null, 2), result.valid);
            } catch (error) {
                showResponse('testResponse', 'Error: ' + error.message, false);
            }
        }

        async function refreshMetrics() {
            try {
                const response = await fetch('/api/metrics');
                const metrics = await response.json();

                document.getElementById('totalRequests').textContent = metrics.TotalRequests || 0;
                document.getElementById('successfulAuths').textContent = metrics.SuccessfulAuths || 0;
                document.getElementById('failedAuths').textContent = metrics.FailedAuths || 0;
                document.getElementById('rateLimitHits').textContent = metrics.RateLimitHits || 0;
                document.getElementById('circuitBreakerHits').textContent = metrics.CircuitBreakerHits || 0;
                document.getElementById('avgLatency').textContent = (metrics.AverageLatencyMs || 0).toFixed(2);
            } catch (error) {
                console.error('Error refreshing metrics:', error);
            }
        }

        async function resetMetrics() {
            try {
                await fetch('/api/metrics/reset', { method: 'POST' });
                await refreshMetrics();
                showResponse('healthResponse', 'Metrics reset successfully', true);
            } catch (error) {
                showResponse('healthResponse', 'Error: ' + error.message, false);
            }
        }

        async function checkHealth() {
            try {
                const response = await fetch('/api/health');
                const result = await response.json();
                showResponse('healthResponse', JSON.stringify(result, null, 2), result.healthy);
            } catch (error) {
                showResponse('healthResponse', 'Error: ' + error.message, false);
            }
        }

        async function checkCircuitBreaker() {
            try {
                const response = await fetch('/api/circuit-breaker');
                const result = await response.json();
                showResponse('healthResponse', 'Circuit Breaker State: ' + result.state, true);
            } catch (error) {
                showResponse('healthResponse', 'Error: ' + error.message, false);
            }
        }

        function buildConfig() {
            return {
                auth_service_url: document.getElementById('authServiceURL').value,
                validate_endpoint: document.getElementById('validateEndpoint').value,
                token_header: document.getElementById('tokenHeader').value,
                token_prefix: document.getElementById('tokenPrefix').value,
                user_id_key: "user_id",
                timeout: document.getElementById('timeout').value,
                max_retries: parseInt(document.getElementById('maxRetries').value),
                retry_wait_min: "100ms",
                retry_wait_max: "2s",
                circuit_breaker_max_requests: 3,
                circuit_breaker_interval: "60s",
                circuit_breaker_timeout: "30s",
                circuit_breaker_threshold: 5,
                rate_limit_enabled: true,
                rate_limit_rps: parseInt(document.getElementById('rateLimitRPS').value),
                max_token_length: 8192,
                validate_url: true,
                log_level: "info",
                log_format: "json"
            };
        }

        function showResponse(elementId, message, success) {
            const element = document.getElementById(elementId);
            element.innerHTML = '<pre>' + message + '</pre>';
            element.style.display = 'block';
            element.style.borderLeft = success ? '4px solid #28a745' : '4px solid #dc3545';
        }

        // Auto-refresh metrics every 5 seconds
        setInterval(refreshMetrics, 5000);
    </script>
</body>
</html>
`
