# Security Guide

This document outlines the security features, best practices, and threat model for the Go Auth Middleware.

## Security Features

### Input Validation

All inputs are validated against strict whitelists:

1. **Token Validation**
   - Maximum length enforced (default: 8192 bytes)
   - Character whitelist: `[A-Za-z0-9\-_.~+/=]` (JWT-safe characters)
   - UTF-8 validation
   - Null byte rejection
   - Control character rejection

2. **Header Validation**
   - Header names validated against `[A-Za-z0-9\-]+`
   - No injection characters allowed
   - Proper HTTP header sanitization

3. **URL Validation**
   - Scheme validation (http/https only)
   - Host validation
   - Malformed URL rejection

### Output Sanitization

All error messages are sanitized to prevent information leakage:

- **Generic error messages** - Users see safe, generic errors
- **Internal logging** - Detailed errors logged internally only
- **No stack traces** - Never exposed to users
- **No configuration details** - Internal URLs, paths hidden

### Rate Limiting

Token bucket algorithm protects against:
- Brute force attacks
- DoS attempts
- Resource exhaustion

Configuration:
```bash
AUTH_RATE_LIMIT_ENABLED=true
AUTH_RATE_LIMIT_RPS=100  # Adjust based on traffic
```

### Circuit Breaker

Prevents cascading failures:
- Opens after N consecutive failures
- Prevents overwhelming failed services
- Automatic recovery attempts
- Configurable thresholds and timeouts

### Secure Defaults

| Setting | Default | Reason |
|---------|---------|--------|
| Timeout | 10s | Prevents hanging requests |
| MaxRetries | 3 | Reasonable retry attempts |
| MaxTokenLength | 8192 | Prevents memory exhaustion |
| RateLimitRPS | 100 | Reasonable default for most apps |
| ValidateURL | true | Prevents malformed URLs |

## Threat Model

### In Scope

This middleware protects against:

1. **Token-based attacks**
   - Oversized tokens (DoS)
   - Malformed tokens
   - Injection attempts in tokens

2. **Network-level attacks**
   - Request flooding (rate limiting)
   - Slowloris (timeouts)
   - Service degradation (circuit breaker)

3. **Information disclosure**
   - Error message leakage
   - Configuration exposure
   - Internal implementation details

4. **Injection attacks**
   - SQL injection in tokens
   - XSS in tokens
   - Command injection
   - Header injection

### Out of Scope

This middleware does NOT protect against:

1. **Authentication service vulnerabilities**
   - The external auth service must be secured independently
   - Token generation/validation is delegated

2. **Application-level vulnerabilities**
   - Business logic flaws
   - Authorization (only handles authentication)
   - Session management

3. **Infrastructure attacks**
   - DDoS at network level
   - TLS/SSL vulnerabilities
   - DNS attacks

4. **Social engineering**
   - Phishing attacks
   - Credential theft
   - Token theft

## Security Best Practices

### 1. Use HTTPS

Always use HTTPS for auth service communication:

```bash
# Good
AUTH_SERVICE_URL=https://auth.example.com

# Bad
AUTH_SERVICE_URL=http://auth.example.com
```

### 2. Secure Configuration

- Store sensitive config in secret managers
- Never commit `.env` files
- Use least-privilege principles
- Rotate credentials regularly

Example with Kubernetes secrets:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-config
type: Opaque
stringData:
  auth-service-url: https://auth.internal.example.com
```

### 3. Monitor Metrics

Track these metrics for security:

- **Failed auth rate** - Spike indicates attack
- **Rate limit hits** - High value indicates abuse
- **Circuit breaker trips** - Service degradation
- **Average latency** - Anomalies may indicate attack

### 4. Set Appropriate Timeouts

Match timeouts to your requirements:

```bash
# Fast internal service
AUTH_TIMEOUT=2s

# Slower external service
AUTH_TIMEOUT=10s

# Never use excessively long timeouts
AUTH_TIMEOUT=60s  # Too long!
```

### 5. Tune Rate Limiting

Set RPS based on legitimate traffic:

```bash
# Low-traffic application
AUTH_RATE_LIMIT_RPS=10

# High-traffic application
AUTH_RATE_LIMIT_RPS=1000

# Per-user rate limiting (implement at app level)
```

### 6. Configure Circuit Breaker

Tune for your failure tolerance:

```bash
# Conservative (fail fast)
AUTH_CB_THRESHOLD=3
AUTH_CB_TIMEOUT=10s

# Tolerant (more retries)
AUTH_CB_THRESHOLD=10
AUTH_CB_TIMEOUT=60s
```

### 7. Enable Structured Logging

Use JSON logging in production:

```bash
AUTH_LOG_LEVEL=info
AUTH_LOG_FORMAT=json
```

Then aggregate with:
- ELK Stack
- Splunk
- CloudWatch Logs
- Datadog

### 8. Implement Defense in Depth

This middleware is one layer. Also implement:

1. **Network security**
   - Firewalls
   - VPNs
   - Private networks

2. **Application security**
   - Input validation at app level
   - Authorization checks
   - CSRF protection

3. **Infrastructure security**
   - Container security
   - Image scanning
   - Runtime protection

### 9. Regular Security Testing

Run security tests regularly:

```bash
# Run security test suite
make test-security

# Run static analysis
make lint

# Run security scanner
make security-scan
```

### 10. Incident Response

Prepare for security incidents:

1. **Detection**
   - Monitor metrics
   - Set up alerts
   - Log aggregation

2. **Response**
   - Incident response plan
   - Circuit breaker manual override
   - Rate limit adjustment

3. **Recovery**
   - Service restoration
   - Post-incident analysis
   - Patch deployment

## Security Testing

### Automated Tests

Run comprehensive security tests:

```bash
make test-security
```

Tests include:
- SQL injection attempts
- XSS attacks
- Command injection
- Header injection
- Path traversal
- Null byte injection
- Unicode attacks
- Oversized payloads
- Error message analysis

### Manual Testing

Use the GUI test harness for manual security testing:

1. Start GUI: `make run-gui`
2. Navigate to http://localhost:3000
3. Test various attack payloads
4. Verify error messages don't leak info
5. Monitor circuit breaker behavior

### Penetration Testing

For production deployments:

1. Conduct regular penetration tests
2. Use tools like:
   - OWASP ZAP
   - Burp Suite
   - Custom scripts

3. Test scenarios:
   - Token manipulation
   - Rate limit bypass attempts
   - Error message analysis
   - Timing attacks

## Vulnerability Disclosure

If you discover a security vulnerability:

1. **DO NOT** open a public issue
2. Email security concerns to: security@example.com
3. Provide details:
   - Description
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (if any)

4. Allow reasonable time for fix
5. Coordinate disclosure timing

## Security Checklist

Before deploying to production:

- [ ] HTTPS enabled for auth service
- [ ] Secrets stored in secret manager
- [ ] Rate limiting configured appropriately
- [ ] Circuit breaker tuned for traffic
- [ ] Timeouts set reasonably
- [ ] JSON logging enabled
- [ ] Metrics monitoring configured
- [ ] Security tests passing
- [ ] Static analysis clean
- [ ] Containers running as non-root
- [ ] Latest dependencies installed
- [ ] Vulnerability scan clean
- [ ] Incident response plan ready

## Compliance

### OWASP Top 10 Coverage

| Risk | Status | Notes |
|------|--------|-------|
| A01:2021 - Broken Access Control | ⚠️ Partial | Handles authentication; authorization is app responsibility |
| A02:2021 - Cryptographic Failures | ✅ Covered | Enforces HTTPS; validates tokens |
| A03:2021 - Injection | ✅ Covered | Input validation prevents injection |
| A04:2021 - Insecure Design | ✅ Covered | Security-first design |
| A05:2021 - Security Misconfiguration | ✅ Covered | Secure defaults; validation |
| A06:2021 - Vulnerable Components | ✅ Covered | Minimal dependencies; kept updated |
| A07:2021 - Identity/Auth Failures | ✅ Covered | Core functionality |
| A08:2021 - Data Integrity Failures | ✅ Covered | Token validation |
| A09:2021 - Security Logging Failures | ✅ Covered | Structured logging |
| A10:2021 - SSRF | ✅ Covered | URL validation |

## Additional Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Go Security Best Practices](https://github.com/guardrails-io/go-security)
- [Circuit Breaker Pattern](https://martinfowler.com/bliki/CircuitBreaker.html)
- [Rate Limiting Strategies](https://cloud.google.com/architecture/rate-limiting-strategies-techniques)
