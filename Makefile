.PHONY: help build test test-unit test-integration test-security test-coverage clean run run-gui run-example run-mock-auth install lint fmt vet docker-build docker-run deps

# Default target
help:
	@echo "Go Auth Middleware - Makefile Commands"
	@echo "======================================="
	@echo "build              - Build all binaries"
	@echo "test               - Run all tests"
	@echo "test-unit          - Run unit tests only"
	@echo "test-integration   - Run integration tests only"
	@echo "test-security      - Run security tests only"
	@echo "test-coverage      - Run tests with coverage report"
	@echo "clean              - Remove build artifacts"
	@echo "run-gui            - Run the GUI test harness"
	@echo "run-example        - Run the example application"
	@echo "run-mock-auth      - Run the mock auth service"
	@echo "install            - Install dependencies"
	@echo "lint               - Run linter (requires golangci-lint)"
	@echo "fmt                - Format code"
	@echo "vet                - Run go vet"
	@echo "docker-build       - Build Docker images"
	@echo "docker-run         - Run with Docker Compose"
	@echo "deps               - Download dependencies"

# Build targets
build: deps
	@echo "Building binaries..."
	@mkdir -p bin
	@go build -o bin/gui ./cmd/gui
	@go build -o bin/example ./examples/simple
	@go build -o bin/mock-auth ./examples/mock-auth-service
	@echo "Build complete! Binaries are in ./bin/"

# Test targets
test: deps
	@echo "Running all tests..."
	@go test -v -race ./...

test-unit: deps
	@echo "Running unit tests..."
	@go test -v -race ./internal/...

test-integration: deps
	@echo "Running integration tests..."
	@go test -v -race ./tests/integration/...

test-security: deps
	@echo "Running security tests..."
	@go test -v -race ./tests/security/...

test-coverage: deps
	@echo "Running tests with coverage..."
	@go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run targets
run-gui: build
	@echo "Starting GUI test harness on http://localhost:3000"
	@AUTH_SERVICE_URL=http://localhost:8081 ./bin/gui

run-example: build
	@echo "Starting example application on http://localhost:8080"
	@AUTH_SERVICE_URL=http://localhost:8081 PORT=8080 ./bin/example

run-mock-auth: build
	@echo "Starting mock auth service on http://localhost:8081"
	@PORT=8081 ./bin/mock-auth

# Dependency management
deps:
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

install: deps
	@echo "Installing tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Code quality
lint:
	@echo "Running linter..."
	@golangci-lint run --timeout=5m

fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@gofmt -s -w .

vet:
	@echo "Running go vet..."
	@go vet ./...

# Docker targets
docker-build:
	@echo "Building Docker images..."
	@docker build -t go-auth-middleware:latest .
	@docker build -t go-auth-middleware-gui:latest -f Dockerfile.gui .
	@docker build -t go-auth-middleware-mock:latest -f Dockerfile.mock .

docker-run:
	@echo "Starting services with Docker Compose..."
	@docker-compose up

# Clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html
	@go clean
	@echo "Clean complete!"

# Security scan (requires gosec)
security-scan:
	@echo "Running security scan..."
	@which gosec > /dev/null || (echo "Installing gosec..." && go install github.com/securego/gosec/v2/cmd/gosec@latest)
	@gosec -fmt=text -no-fail ./...
